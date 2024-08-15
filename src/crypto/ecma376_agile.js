'use strict';

const crypto = require('crypto');
const cfb = require('cfb');
const xmlUtil = require('../util/xml');
const zip = require('../util/zip');


const ENCRYPTION_INFO_PREFIX = Buffer.from([0x04, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00]); // First 4 bytes are the version number, second 4 bytes are reserved.
const PACKAGE_ENCRYPTION_CHUNK_SIZE = 4096;
const PACKAGE_OFFSET = 8; // First 8 bytes are the size of the stream

// Block keys used for encryption
const BLOCK_KEYS = {
  dataIntegrity: {
    hmacKey: Buffer.from([0x5f, 0xb2, 0xad, 0x01, 0x0c, 0xb9, 0xe1, 0xf6]),
    hmacValue: Buffer.from([0xa0, 0x67, 0x7f, 0x02, 0xb2, 0x2c, 0x84, 0x33]),
  },
  key: Buffer.from([0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6]),
  verifierHash: {
    input: Buffer.from([0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79]),
    value: Buffer.from([0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e]),
  },
};

const Encryptor = {
  /**
   * Calculate a hash of the concatenated buffers with the given algorithm.
   * @param {string} algorithm - The hash algorithm.
   * @return {Buffer} The hash
   */
  hash(algorithm, ...buffers) {
    const hash = crypto.createHash(algorithm);
    hash.update(Buffer.concat(buffers));
    return hash.digest();
  },

  /**
   * Decrypt the data with the given password
   * @param {Buffer} data - The data to decrypt
   * @param {string} password - The password
   * @return {Promise.<Buffer>} The decrypted data
   */
  async decrypt(data, password) {
    let {encryptionInfoBuffer, encryptedPackageBuffer} = data;

    // In the browser the CFB content is an array. Convert to a Buffer.
    if (!Buffer.isBuffer(encryptionInfoBuffer)) encryptionInfoBuffer = Buffer.from(encryptionInfoBuffer);
    if (!Buffer.isBuffer(encryptedPackageBuffer)) encryptedPackageBuffer = Buffer.from(encryptedPackageBuffer);


    // Parse the encryption info XML into an object
    const encryptionInfo = await this.parseEncryptionInfo(encryptionInfoBuffer);

    const valid = this.verifyPassword(password, encryptionInfo);
    if (!valid) throw new Error('The password is incorrect');

    // Convert the password into an encryption key
    const key = this.convertPasswordToKey(
        password,
        encryptionInfo.key.hashAlgorithm,
        encryptionInfo.key.saltValue,
        encryptionInfo.key.spinCount,
        encryptionInfo.key.keyBits,
        BLOCK_KEYS.key,
    );

    // Use the key to decrypt the package key
    const packageKey = this.crypt(
        false,
        encryptionInfo.key.cipherAlgorithm,
        encryptionInfo.key.cipherChaining,
        key,
        encryptionInfo.key.saltValue,
        encryptionInfo.key.encryptedKeyValue,
    );

    // Use the package key to decrypt the package
    const outputFileBuffer = this.cryptPackage(
        false,
        encryptionInfo.package.cipherAlgorithm,
        encryptionInfo.package.cipherChaining,
        encryptionInfo.package.hashAlgorithm,
        encryptionInfo.package.blockSize,
        encryptionInfo.package.saltValue,
        packageKey,
        encryptedPackageBuffer,
    );

    const isValidZip = zip.isValidZip(outputFileBuffer);
    if (!isValidZip) {
      throw new Error('The password is incorrect');
    }

    return outputFileBuffer;
  },

  /**
   * Parse the encryption info from the XML/buffer
   * @param {Buffer} buffer - The buffer
   * @return {Promise.<{}>} The parsed encryption info object
   * @private
   */
  async parseEncryptionInfo(buffer) {
    // Pull off the prefix and convert to string
    const xml = buffer.slice(ENCRYPTION_INFO_PREFIX.length).toString('utf8');
    const doc = await xmlUtil.getAgileEncInfo(xml);

    const {keyData, keyEncryptors} = doc;
    const {cipherAlgorithm, cipherChaining, saltValue, hashAlgorithm, blockSize} = keyData;
    const encryptedKeyNode = keyEncryptors.keyEncryptor['p:encryptedKey'];

    return {
      package: {
        cipherAlgorithm,
        cipherChaining,
        saltValue: Buffer.from(saltValue, 'base64'),
        hashAlgorithm,
        blockSize,
      },
      key: {
        encryptedKeyValue: Buffer.from(encryptedKeyNode.encryptedKeyValue, 'base64'),
        encryptedVerifierHashInput: Buffer.from(encryptedKeyNode.encryptedVerifierHashInput, 'base64'),
        encryptedVerifierHashValue: Buffer.from(encryptedKeyNode.encryptedVerifierHashValue, 'base64'),
        cipherAlgorithm: encryptedKeyNode.cipherAlgorithm,
        cipherChaining: encryptedKeyNode.cipherChaining,
        saltValue: Buffer.from(encryptedKeyNode.saltValue, 'base64'),
        hashAlgorithm: encryptedKeyNode.hashAlgorithm,
        spinCount: encryptedKeyNode.spinCount,
        keyBits: encryptedKeyNode.keyBits,
      },
    };
  },

  /**
   * Convert a password into an encryption key
   * @param {string} password - The password
   * @param {string} hashAlgorithm - The hash algoritm
   * @param {Buffer} saltValue - The salt value
   * @param {number} spinCount - The spin count
   * @param {number} keyBits - The length of the key in bits
   * @param {Buffer} blockKey - The block key
   * @return {Buffer} The encryption key
   * @private
   */
  convertPasswordToKey(password, hashAlgorithm, saltValue, spinCount, keyBits, blockKey) {
    // Password must be in unicode buffer
    const passwordBuffer = Buffer.from(password, 'utf16le');

    // Generate the initial hash
    let key = this.hash(hashAlgorithm, saltValue, passwordBuffer);

    // Now regenerate until spin count
    for (let i = 0; i < spinCount; i++) {
      const iterator = this.createUInt32LEBuffer(i);
      key = this.hash(hashAlgorithm, iterator, key);
    }

    // Now generate the final hash
    key = this.hash(hashAlgorithm, key, blockKey);

    // Truncate or pad as needed to get to length of keyBits
    const keyBytes = keyBits / 8;
    if (key.length < keyBytes) {
      const tmp = Buffer.alloc(keyBytes, 0x36);
      key.copy(tmp);
      key = tmp;
    } else if (key.length > keyBytes) {
      key = key.slice(0, keyBytes);
    }

    return key;
  },

  /**
   * Encrypt/decrypt the package
   * @param {boolean} encrypt - True to encrypt, false to decrypt
   * @param {string} cipherAlgorithm - The cipher algorithm
   * @param {string} cipherChaining - The cipher chaining mode
   * @param {string} hashAlgorithm - The hash algorithm
   * @param {number} blockSize - The IV block size
   * @param {Buffer} saltValue - The salt
   * @param {Buffer} key - The encryption key
   * @param {Buffer} input - The package input
   * @return {Buffer} The output
   * @private
   */
  cryptPackage(encrypt, cipherAlgorithm, cipherChaining, hashAlgorithm, blockSize, saltValue, key, input) {
    // The first 8 bytes is supposed to be the length, but it seems like it is really the length - 4..
    const outputChunks = [];
    const offset = encrypt ? 0 : PACKAGE_OFFSET;

    // The package is encoded in chunks. Encrypt/decrypt each and concat.
    let i = 0;
    let start = 0;
    let end = 0;
    while (end < input.length) {
      start = end;
      end = start + PACKAGE_ENCRYPTION_CHUNK_SIZE;
      if (end > input.length) end = input.length;

      // Grab the next chunk
      let inputChunk = input.slice(start + offset, end + offset);

      // Pad the chunk if it is not an integer multiple of the block size
      const remainder = inputChunk.length % blockSize;
      if (remainder) inputChunk = Buffer.concat([inputChunk, Buffer.alloc(blockSize - remainder)]);

      // Create the initialization vector
      const iv = this.createIV(hashAlgorithm, saltValue, blockSize, i);

      // Encrypt/decrypt the chunk and add it to the array
      const outputChunk = this.crypt(encrypt, cipherAlgorithm, cipherChaining, key, iv, inputChunk);
      outputChunks.push(outputChunk);

      i++;
    }

    // Concat all of the output chunks.
    let output = Buffer.concat(outputChunks);

    if (encrypt) {
      // Put the length of the package in the first 8 bytes
      output = Buffer.concat([this.createUInt32LEBuffer(input.length, PACKAGE_OFFSET), output]);
    } else {
      // Truncate the buffer to the size in the prefix
      const length = input.readUInt32LE(0);
      output = output.slice(0, length);
    }

    return output;
  },

  /**
   * Create a buffer of an integer encoded as a uint32le
   * @param {number} value - The integer to encode
   * @param {number} [bufferSize=4] The output buffer size in bytes
   * @return {Buffer} The buffer
   * @private
   */
  createUInt32LEBuffer(value, bufferSize = 4) {
    const buffer = Buffer.alloc(bufferSize);
    buffer.writeUInt32LE(value, 0);
    return buffer;
  },

  /**
   * Create an initialization vector (IV)
   * @param {string} hashAlgorithm - The hash algorithm
   * @param {Buffer} saltValue - The salt value
   * @param {number} blockSize - The size of the IV
   * @param {Buffer|number} blockKey - The block key or an int to convert to a buffer
   * @return {Buffer} The IV
   * @private
   */
  createIV(hashAlgorithm, saltValue, blockSize, blockKey) {
    // Create the block key from the current index
    if (typeof blockKey === 'number') blockKey = this.createUInt32LEBuffer(blockKey);

    // Create the initialization vector by hashing the salt with the block key.
    // Truncate or pad as needed to meet the block size.
    let iv = this.hash(hashAlgorithm, saltValue, blockKey);
    if (iv.length < blockSize) {
      const tmp = Buffer.alloc(blockSize, 0x36);
      iv.copy(tmp);
      iv = tmp;
    } else if (iv.length > blockSize) {
      iv = iv.slice(0, blockSize);
    }

    return iv;
  },

  /**
   * Encrypt/decrypt input
   * @param {boolean} encrypt - True to encrypt, false to decrypt
   * @param {string} cipherAlgorithm - The cipher algorithm
   * @param {string} cipherChaining - The cipher chaining mode
   * @param {Buffer} key - The encryption key
   * @param {Buffer} iv - The initialization vector
   * @param {Buffer} input - The input
   * @return {Buffer} The output
   * @private
   */
  crypt(encrypt, cipherAlgorithm, cipherChaining, key, iv, input) {
    let algorithm = `${cipherAlgorithm.toLowerCase()}-${key.length * 8}`;
    if (cipherChaining === 'ChainingModeCBC') algorithm += '-cbc';
    else throw new Error(`Unknown cipher chaining: ${cipherChaining}`);

    const cipher = crypto[encrypt ? 'createCipheriv' : 'createDecipheriv'](algorithm, key, iv);
    cipher.setAutoPadding(false);
    let output = cipher.update(input);
    output = Buffer.concat([output, cipher.final()]);
    return output;
  },

  /**
   * Encrypt the data with the password.
   * @param {Buffer} data - The data to encrypt
   * @param {string} password - The password
   * @return {Buffer} The encrypted data
   */
  encrypt(data, password) {
    // Generate a random key to use to encrypt the document. Excel uses 32 bytes. We'll use the password to encrypt this key.
    // N.B. The number of bits needs to correspond to an algorithm available in crypto (e.g. aes-256-cbc).
    const packageKey = crypto.randomBytes(32);

    // Create the encryption info. We'll use this for all of the encryption operations and for building the encryption info XML entry
    const encryptionInfo = {
      package: { // Info on the encryption of the package.
        cipherAlgorithm: 'AES', // Cipher algorithm to use. Excel uses AES.
        cipherChaining: 'ChainingModeCBC', // Cipher chaining mode to use. Excel uses CBC.
        saltValue: crypto.randomBytes(16), // Random value to use as encryption salt. Excel uses 16 bytes.
        hashAlgorithm: 'SHA512', // Hash algorithm to use. Excel uses SHA512.
        hashSize: 64, // The size of the hash in bytes. SHA512 results in 64-byte hashes
        blockSize: 16, // The number of bytes used to encrypt one block of data. It MUST be at least 2, no greater than 4096, and a multiple of 2. Excel uses 16
        keyBits: packageKey.length * 8, // The number of bits in the package key.
      },
      key: { // Info on the encryption of the package key.
        cipherAlgorithm: 'AES', // Cipher algorithm to use. Excel uses AES.
        cipherChaining: 'ChainingModeCBC', // Cipher chaining mode to use. Excel uses CBC.
        saltValue: crypto.randomBytes(16), // Random value to use as encryption salt. Excel uses 16 bytes.
        hashAlgorithm: 'SHA512', // Hash algorithm to use. Excel uses SHA512.
        hashSize: 64, // The size of the hash in bytes. SHA512 results in 64-byte hashes
        blockSize: 16, // The number of bytes used to encrypt one block of data. It MUST be at least 2, no greater than 4096, and a multiple of 2. Excel uses 16
        spinCount: 100000, // The number of times to iterate on a hash of a password. It MUST NOT be greater than 10,000,000. Excel uses 100,000.
        keyBits: 256, // The length of the key to generate from the password. Must be a multiple of 8. Excel uses 256.
      },
    };

    /* Package Encryption */

    // Encrypt package using the package key.
    const encryptedPackage = this.cryptPackage(
        true,
        encryptionInfo.package.cipherAlgorithm,
        encryptionInfo.package.cipherChaining,
        encryptionInfo.package.hashAlgorithm,
        encryptionInfo.package.blockSize,
        encryptionInfo.package.saltValue,
        packageKey,
        data,
    );

    /* Data Integrity */

    // Create the data integrity fields used by clients for integrity checks.
    // First generate a random array of bytes to use in HMAC. The docs say to use the same length as the key salt, but Excel seems to use 64.
    const hmacKey = crypto.randomBytes(64);

    // Then create an initialization vector using the package encryption info and the appropriate block key.
    const hmacKeyIV = this.createIV(
        encryptionInfo.package.hashAlgorithm,
        encryptionInfo.package.saltValue,
        encryptionInfo.package.blockSize,
        BLOCK_KEYS.dataIntegrity.hmacKey,
    );

    // Use the package key and the IV to encrypt the HMAC key
    const encryptedHmacKey = this.crypt(
        true,
        encryptionInfo.package.cipherAlgorithm,
        encryptionInfo.package.cipherChaining,
        packageKey,
        hmacKeyIV,
        hmacKey);

    // Now create the HMAC
    const hmacValue = this.hmac(encryptionInfo.package.hashAlgorithm, hmacKey, encryptedPackage);

    // Next generate an initialization vector for encrypting the resulting HMAC value.
    const hmacValueIV = this.createIV(
        encryptionInfo.package.hashAlgorithm,
        encryptionInfo.package.saltValue,
        encryptionInfo.package.blockSize,
        BLOCK_KEYS.dataIntegrity.hmacValue,
    );

    // Now encrypt the value
    const encryptedHmacValue = this.crypt(
        true,
        encryptionInfo.package.cipherAlgorithm,
        encryptionInfo.package.cipherChaining,
        packageKey,
        hmacValueIV,
        hmacValue,
    );

    // Put the encrypted key and value on the encryption info
    encryptionInfo.dataIntegrity = {
      encryptedHmacKey,
      encryptedHmacValue,
    };

    /* Key Encryption */

    // Convert the password to an encryption key
    const key = this.convertPasswordToKey(
        password,
        encryptionInfo.key.hashAlgorithm,
        encryptionInfo.key.saltValue,
        encryptionInfo.key.spinCount,
        encryptionInfo.key.keyBits,
        BLOCK_KEYS.key,
    );

    // Encrypt the package key with the
    encryptionInfo.key.encryptedKeyValue = this.crypt(
        true,
        encryptionInfo.key.cipherAlgorithm,
        encryptionInfo.key.cipherChaining,
        key,
        encryptionInfo.key.saltValue,
        packageKey);

    /* Verifier hash */

    // Create a random byte array for hashing
    const verifierHashInput = crypto.randomBytes(16);

    // Create an encryption key from the password for the input
    const verifierHashInputKey = this.convertPasswordToKey(
        password,
        encryptionInfo.key.hashAlgorithm,
        encryptionInfo.key.saltValue,
        encryptionInfo.key.spinCount,
        encryptionInfo.key.keyBits,
        BLOCK_KEYS.verifierHash.input,
    );

    // Use the key to encrypt the verifier input
    encryptionInfo.key.encryptedVerifierHashInput = this.crypt(
        true,
        encryptionInfo.key.cipherAlgorithm,
        encryptionInfo.key.cipherChaining,
        verifierHashInputKey,
        encryptionInfo.key.saltValue,
        verifierHashInput,
    );

    // Create a hash of the input
    const verifierHashValue = this.hash(encryptionInfo.key.hashAlgorithm, verifierHashInput);

    // Create an encryption key from the password for the hash
    const verifierHashValueKey = this.convertPasswordToKey(
        password,
        encryptionInfo.key.hashAlgorithm,
        encryptionInfo.key.saltValue,
        encryptionInfo.key.spinCount,
        encryptionInfo.key.keyBits,
        BLOCK_KEYS.verifierHash.value,
    );

    // Use the key to encrypt the hash value
    encryptionInfo.key.encryptedVerifierHashValue = this.crypt(
        true,
        encryptionInfo.key.cipherAlgorithm,
        encryptionInfo.key.cipherChaining,
        verifierHashValueKey,
        encryptionInfo.key.saltValue,
        verifierHashValue,
    );

    const encryptionInfoXml = xmlUtil.buildAgileEncInfoXml(encryptionInfo);

    // Convert to a buffer and prefix with the appropriate bytes
    const encryptionInfoBuffer = Buffer.concat([ENCRYPTION_INFO_PREFIX, Buffer.from(encryptionInfoXml, 'utf8')]);

    // Create a new CFB
    let output = cfb.utils.cfb_new();

    // Add the encryption info and encrypted package
    cfb.utils.cfb_add(output, 'EncryptionInfo', encryptionInfoBuffer);
    cfb.utils.cfb_add(output, 'EncryptedPackage', encryptedPackage);

    // Delete the SheetJS entry that is added at initialization
    cfb.utils.cfb_del(output, '\u0001Sh33tJ5');

    // Write to a buffer and return
    output = cfb.write(output);

    // The cfb library writes to a Uint8array in the browser. Convert to a Buffer.
    if (!Buffer.isBuffer(output)) output = Buffer.from(output);

    return output;
  },

  /**
   * Calculate an HMAC of the concatenated buffers with the given algorithm and key
   * @param {string} algorithm - The algorithm.
   * @param {string} key - The key
   * @param {Array.<Buffer>} buffers - The buffer to concat and HMAC
   * @return {Buffer} The HMAC
   * @private
   */
  hmac(algorithm, key, ...buffers) {
    algorithm = algorithm.toLowerCase();
    const hashes = crypto.getHashes();
    if (hashes.indexOf(algorithm) < 0) throw new Error(`HMAC algorithm '${algorithm}' not supported!`);

    const hmac = crypto.createHmac(algorithm, key);
    hmac.update(Buffer.concat(buffers));
    return hmac.digest();
  },

  verifyPassword(password, encryptionInfo) {
    const verifierHashInputKey = this.convertPasswordToKey(
        password,
        encryptionInfo.key.hashAlgorithm,
        encryptionInfo.key.saltValue,
        encryptionInfo.key.spinCount,
        encryptionInfo.key.keyBits,
        BLOCK_KEYS.verifierHash.input,
    );

    const verifierHashValueKey = this.convertPasswordToKey(
        password,
        encryptionInfo.key.hashAlgorithm,
        encryptionInfo.key.saltValue,
        encryptionInfo.key.spinCount,
        encryptionInfo.key.keyBits,
        BLOCK_KEYS.verifierHash.value,
    );

    const verifierHashInput = this.crypt(
        false,
        encryptionInfo.key.cipherAlgorithm,
        encryptionInfo.key.cipherChaining,
        verifierHashInputKey,
        encryptionInfo.key.saltValue,
        encryptionInfo.key.encryptedVerifierHashInput,
    );

    const verifierHashValue = this.crypt(
        false,
        encryptionInfo.key.cipherAlgorithm,
        encryptionInfo.key.cipherChaining,
        verifierHashValueKey,
        encryptionInfo.key.saltValue,
        encryptionInfo.key.encryptedVerifierHashValue,
    );

    const actualHash = this.hash(encryptionInfo.key.hashAlgorithm, verifierHashInput);
    return actualHash.equals(verifierHashValue);
  },
};
module.exports = Encryptor;
