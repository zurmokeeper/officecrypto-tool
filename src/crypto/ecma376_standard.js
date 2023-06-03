/* eslint-disable require-jsdoc */
'use strict';

const crypto = require('crypto');
const cfb = require('cfb');

const convertPasswordToKey = exports.convertPasswordToKey = function convertPasswordToKey(password, algId, algIdHash, providerType, keySize, saltSize, salt) {
  const ITER_COUNT = 50000;
  const cbRequiredKeyLength = keySize / 8;

  const passwordBuf = Buffer.from(password, 'utf16le');
  let saltedPasswordHash = crypto.createHash('sha1').update(salt).update(passwordBuf).digest();

  for (let i = 0; i < ITER_COUNT; i++) {
    const ibytes = Buffer.alloc(4);
    ibytes.writeUInt32LE(i, 0);
    saltedPasswordHash = crypto.createHash('sha1').update(ibytes).update(saltedPasswordHash).digest();
  }

  const block = Buffer.alloc(4);
  const hfinal = crypto.createHash('sha1').update(saltedPasswordHash).update(block).digest();
  const cbHash = 20;

  let buf1 = Buffer.alloc(64, 0x36);
  buf1 = Buffer.concat([xorBytes(hfinal, buf1.slice(0, cbHash)), buf1.slice(cbHash)]);
  const x1 = crypto.createHash('sha1').update(buf1).digest();

  let buf2 = Buffer.alloc(64, 0x5C);
  buf2 = Buffer.concat([xorBytes(hfinal, buf2.slice(0, cbHash)), buf2.slice(cbHash)]);
  const x2 = crypto.createHash('sha1').update(buf2).digest();
  const x3 = Buffer.concat([x1, x2]);
  const keyDerived = x3.slice(0, cbRequiredKeyLength);

  return keyDerived;
};

function xorBytes(a, b) {
  const result = [];
  for (let i = 0; i < a.length; i++) {
    result.push(a[i] ^ b[i]);
  }
  return Buffer.from(result);
}

exports.verifyKey = function verifyKey(key, encryptedVerifier, encryptedVerifierHash) {
  // In the browser environment. Convert to a Buffer.
  if (!Buffer.isBuffer(encryptedVerifier)) encryptedVerifier = Buffer.from(encryptedVerifier);
  if (!Buffer.isBuffer(encryptedVerifierHash)) encryptedVerifierHash = Buffer.from(encryptedVerifierHash);

  const aes = crypto.createDecipheriv('aes-128-ecb', key, Buffer.alloc(0));
  aes.setAutoPadding(false);
  let verifier = aes.update(encryptedVerifier);
  verifier = Buffer.concat([verifier, aes.final()]);
  const expectedHash = crypto.createHash('sha1').update(verifier).digest();
  const decryptor = crypto.createDecipheriv('aes-128-ecb', key, Buffer.alloc(0));
  decryptor.setAutoPadding(false);
  let verifierHash = decryptor.update(encryptedVerifierHash);
  verifierHash = Buffer.concat([verifierHash, decryptor.final()]).slice(0, 20);
  return expectedHash.equals(verifierHash);
};

exports.decrypt = function decrypt(key, input) {
  const outputChunks = [];
  const offset = 8;
  const blockSize = 16;

  // In the browser environment. Convert to a Buffer.
  if (!Buffer.isBuffer(input)) input = Buffer.from(input);

  // The package is encoded in chunks. Encrypt/decrypt each and concat.
  let start = 0; let end = 0;
  while (end < input.length) {
    start = end;
    end = start + 4096;
    if (end > input.length) end = input.length;

    // Grab the next chunk
    let inputChunk = input.slice(start + offset, end + offset);

    // Pad the chunk if it is not an integer multiple of the block size
    const remainder = inputChunk.length % blockSize;
    if (remainder) inputChunk = Buffer.concat([inputChunk, Buffer.alloc(blockSize - remainder)]);

    // Encrypt/decrypt the chunk and add it to the array
    const cipher = crypto.createDecipheriv('aes-128-ecb', key, '');
    cipher.setAutoPadding(false);
    const outputChunk = Buffer.concat([cipher.update(inputChunk), cipher.final()]);
    outputChunks.push(outputChunk);
  }

  // Concat all of the output chunks.
  let output = Buffer.concat(outputChunks);
  // Truncate the buffer to the size in the prefix
  const length = input.readUInt32LE(0);
  output = output.slice(0, length);
  return output;
};

const encrypt = exports.encrypt = function encrypt(key, input) {
  const outputChunks = [];
  const offset = 0;
  const PACKAGE_OFFSET = 8;
  const blockSize = 16;

  // The package is encoded in chunks. Encrypt/decrypt each and concat.
  let start = 0; let end = 0;
  while (end < input.length) {
    start = end;
    end = start + 4096;
    if (end > input.length) end = input.length;

    // Grab the next chunk
    let inputChunk = input.slice(start + offset, end + offset);

    // Pad the chunk if it is not an integer multiple of the block size
    const remainder = inputChunk.length % blockSize;
    if (remainder) inputChunk = Buffer.concat([inputChunk, Buffer.alloc(blockSize - remainder)]);

    // Encrypt/decrypt the chunk and add it to the array
    const cipher = crypto.createCipheriv('aes-128-ecb', key, '');
    cipher.setAutoPadding(false);
    const outputChunk = Buffer.concat([cipher.update(inputChunk), cipher.final()]);
    outputChunks.push(outputChunk);
  }

  // Concat all of the output chunks.
  let output = Buffer.concat(outputChunks);

  // Put the length of the package in the first 8 bytes
  output = Buffer.concat([createUInt32LEBuffer(input.length, PACKAGE_OFFSET), output]);

  return output;
};

function createUInt32LEBuffer(value, bufferSize = 4) {
  const buffer = Buffer.alloc(bufferSize);
  buffer.writeUInt32LE(value, 0);
  return buffer;
}

function genVerifier(key) {
  const verifierHashInput = crypto.randomBytes(16);
  const aes = crypto.createCipheriv('aes-128-ecb', key, Buffer.alloc(0));
  aes.setAutoPadding(false);
  const verifierHashInputValue = Buffer.concat([aes.update(verifierHashInput), aes.final()]);

  let verifierHashInputKey = crypto.createHash('sha1').update(verifierHashInput).digest();
  const blockSize = 16;
  const remainder = verifierHashInputKey.length % blockSize;
  if (remainder) verifierHashInputKey = Buffer.concat([verifierHashInputKey, Buffer.alloc(blockSize - remainder)]);

  const aes2 = crypto.createCipheriv('aes-128-ecb', key, Buffer.alloc(0));
  aes2.setAutoPadding(false);
  const verifierHashInputKeyValue = Buffer.concat([aes2.update(verifierHashInputKey), aes2.final()]);
  return {encryptedVerifier: verifierHashInputValue, encryptedVerifierHash: verifierHashInputKeyValue};
}

function buildEncryptionInfo(key, keyDataSaltValue) {
  const blob = Buffer.alloc(224);
  cfb.utils.prep_blob(blob, 0);

  blob.write_shift(2, 0x0004);
  blob.write_shift(2, 0x0002);
  blob.write_shift(4, 0x24); // EncryptionHeaderFlags
  blob.write_shift(4, 0x8c); // 140  EncryptionHeaderSize
  blob.write_shift(4, 0x24); // Flags
  blob.write_shift(4, 0x00); // SizeExtra
  blob.write_shift(4, 0x660E); // AlgID
  blob.write_shift(4, 0x8004); // AlgIDHash
  blob.write_shift(4, 0x80); // KeySize  128
  blob.write_shift(4, 0x18); // ProviderType;
  blob.write_shift(4, 0x00); // Reserved1
  blob.write_shift(4, 0x00); // Reserved2

  // The entire EncryptionHeaderSize is 140 bytes, the above is already 32 bytes, leaving 108 bytes, since it is utf16le
  // so providerName = 108/2 = 54

  const providerName = 'Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)';
  blob.write_shift(54, providerName, 'utf16le');

  blob.write_shift(4, 0x10); // SaltSize

  const {encryptedVerifier, encryptedVerifierHash} = genVerifier(key);

  blob.write_shift(16, keyDataSaltValue.toString('hex'), 'hex'); // Salt
  blob.write_shift(16, encryptedVerifier.toString('hex'), 'hex'); // EncryptedVerifier
  blob.write_shift(4, 0x14); // VerifierHashSize
  blob.write_shift(32, encryptedVerifierHash.toString('hex'), 'hex'); // EncryptedVerifierHash

  return blob;
}

function buildEncryptionPackage(key, input) {
  const output = encrypt(key, input);
  return output;
}

exports.encryptStandard = function encryptStandard(input, password) {
  // Create a new CFB
  let output = cfb.utils.cfb_new();

  const KeySize = 128;
  const AlgID = 0x660E;
  const AlgIDHash = 0x8004;
  const ProviderType = 0x18;
  const saltSize = 16;
  const keyDataSaltValue = crypto.randomBytes(16);
  const key = convertPasswordToKey(password, AlgID, AlgIDHash, ProviderType, KeySize, saltSize, keyDataSaltValue);

  const encryptionInfoBuffer = buildEncryptionInfo(key, keyDataSaltValue);
  const encryptedPackage = buildEncryptionPackage(key, input);

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
};
