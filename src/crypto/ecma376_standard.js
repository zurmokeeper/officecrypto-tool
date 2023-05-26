/* eslint-disable require-jsdoc */
'use strict';

const crypto = require('crypto');

exports.makeKeyFromPassword = function makeKeyFromPassword(password, algId, algIdHash, providerType, keySize, saltSize, salt) {
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

function verifyKey(key, encryptedVerifier, encryptedVerifierHash) {
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
}

exports.decrypt = function decrypt(key, input) {
  const outputChunks = [];
  const offset = 8;
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

exports.encrypt = function encrypt(key, input) {
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
