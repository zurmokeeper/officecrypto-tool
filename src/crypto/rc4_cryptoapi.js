/* eslint-disable valid-jsdoc */

const crypto = require('crypto');
const CryptoJS = require('crypto-js');

/**
 * @desc
 */
function convertPasswordToKey(password, salt, keyLength, block, algIdHash = 0x00008004) {
  // https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/12ec1195-af2d-44e6-8c73-003e79e635d5?redirectedfrom=MSDN
  password = Buffer.from(password, 'utf16le');
  const h0 = crypto.createHash('sha1').update(Buffer.concat([salt, password])).digest();
  const blockBytes = Buffer.alloc(4);
  blockBytes.writeUInt32LE(block, 0);
  const hFinal = crypto.createHash('sha1').update(Buffer.concat([h0, blockBytes])).digest();
  let key;
  if (keyLength === 40) {
    key = Buffer.concat([hFinal.slice(0, 5), Buffer.alloc(11)]);
  } else {
    key = hFinal.slice(0, keyLength / 8);
  }
  return key;
}

/**
 * @desc Only node.js is supported.
 */
// exports.verifyPassword = function verifyPassword(password, salt, keySize, encryptedVerifier, encryptedVerifierHash, algId = 0x00006801, block = 0) {
//   // https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/fbfe41db-ca02-413a-a3bb-609fa0b25cd3?redirectedfrom=MSDN
//   const key = convertPasswordToKey(password, salt, keySize, block);
//   const cipher = crypto.createDecipheriv('rc4', key, '');
//   const verifier = Buffer.concat([cipher.update(encryptedVerifier)]);
//   const verifierHash = Buffer.concat([cipher.update(encryptedVerifierHash), cipher.final()]);

//   const hash = crypto.createHash('sha1').update(verifier).digest();
//   //   console.log([verifierHash, hash]);
//   return Buffer.compare(verifierHash, hash) === 0;
// };

/**
 * @desc Because crypto's front-end compatibility library, crypto-browserify, does not support the rc4 algorithm,
 * we have switched to crypto-js to handle the rc4 algorithm for both node.js and the browser side.
 * @returns
 */
exports.verifyPassword = function verifyPassword(password, salt, keySize, encryptedVerifier, encryptedVerifierHash, algId = 0x00006801, block = 0) {
  // https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/fbfe41db-ca02-413a-a3bb-609fa0b25cd3?redirectedfrom=MSDN
  const key = convertPasswordToKey(password, salt, keySize, block);
  const cipher = CryptoJS.algo.RC4.createDecryptor(CryptoJS.lib.WordArray.create(key));
  const verifier = cipher.finalize(CryptoJS.lib.WordArray.create(encryptedVerifier));
  const verifierHash = cipher.finalize(CryptoJS.lib.WordArray.create(encryptedVerifierHash));

  const hash = CryptoJS.SHA1(verifier);
  //   console.log([verifierHash, hash]);
  return verifierHash.toString(CryptoJS.enc.Hex) === hash.toString(CryptoJS.enc.Hex);
};

/**
 * @desc
 */
exports.decrypt = function decrypt(password, salt, KeySize, input, blocksize = 0x200, block = 0) {
  let start = 0;
  let end = 0;
  let key = convertPasswordToKey(password, salt, KeySize, block);

  const outputChunks = [];
  while (end < input.length) {
    start = end;
    end = start + blocksize;
    if (end > input.length) end = input.length;

    // Grab the next chunk
    const inputChunk = input.slice(start, end);

    // Only node.js is supported.
    // Encrypt/decrypt the chunk and add it to the array
    // const cipher = crypto.createDecipheriv('rc4', key, '');
    // const outputChunk = Buffer.concat([cipher.update(inputChunk), cipher.final()]);

    // Supports both node.js and browsers.
    const cipher = CryptoJS.algo.RC4.createDecryptor(CryptoJS.lib.WordArray.create(key));
    let outputChunk = cipher.finalize(CryptoJS.lib.WordArray.create(inputChunk));
    outputChunk = Buffer.from(outputChunk.toString(CryptoJS.enc.Hex), 'hex');

    outputChunks.push(outputChunk);

    block += 1;
    key = convertPasswordToKey(password, salt, KeySize, block);
  }

  // Concat all of the output chunks.
  const output = Buffer.concat(outputChunks);
  return output;
};
