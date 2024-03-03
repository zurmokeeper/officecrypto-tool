/* eslint-disable valid-jsdoc */


const crypto = require('crypto');
const CryptoJS = require('crypto-js');

/**
 * @desc
 */
function convertPasswordToKey(password, salt, block) {
  password = Buffer.from(password, 'utf16le');
  const h0 = crypto.createHash('md5').update(password).digest();
  let truncatedHash = h0.slice(0, 5);
  let intermediateBuffer = Buffer.concat([truncatedHash, salt]);
  intermediateBuffer = Buffer.concat(Array(16).fill(intermediateBuffer));
  intermediateBuffer = crypto.createHash('md5').update(intermediateBuffer).digest();

  truncatedHash = intermediateBuffer.slice(0, 5);
  const blockBytes = Buffer.alloc(4);
  blockBytes.writeInt32LE(block, 0);
  const finalBuffer = Buffer.concat([truncatedHash, blockBytes]);
  const hFinal = crypto.createHash('md5').update(finalBuffer).digest();
  const key = hFinal.slice(0, 128 / 8);
  return key;
}

/**
 * @desc Only node.js is supported.
 * @returns
 */
// exports.verifyPassword = function verifyPw(password, salt, encryptedVerifier, encryptedVerifierHash) {
//   const block = 0;
//   const key = convertPasswordToKey(password, salt, block);
//   const cipher = crypto.createDecipheriv('rc4', key, '');
//   const verifier = Buffer.concat([cipher.update(encryptedVerifier)]);

//   const hash = crypto.createHash('md5').update(verifier).digest();

//   const verifierHash = Buffer.concat([cipher.update(encryptedVerifierHash), cipher.final()]);

//   return verifierHash.equals(hash);
// };

/**
 * @desc Because crypto's front-end compatibility library, crypto-browserify, does not support the rc4 algorithm,
 * we have switched to crypto-js to handle the rc4 algorithm for both node.js and the browser side.
 * @returns
 */
exports.verifyPassword = function verifyPw(password, salt, encryptedVerifier, encryptedVerifierHash) {
  const block = 0;
  const key = convertPasswordToKey(password, salt, block);

  const cipher = CryptoJS.algo.RC4.createDecryptor(CryptoJS.lib.WordArray.create(key));
  const verifier = cipher.finalize(CryptoJS.lib.WordArray.create(encryptedVerifier));

  const hash = CryptoJS.MD5(verifier);

  const verifierHash = cipher.finalize(CryptoJS.lib.WordArray.create(encryptedVerifierHash));

  return verifierHash.toString(CryptoJS.enc.Hex) === hash.toString(CryptoJS.enc.Hex);
};

/**
 * @desc
 */
exports.decrypt = function decrypt(password, salt, input, blocksize = 0x200) {
  let start = 0;
  let end = 0;
  let block = 0;
  let key = convertPasswordToKey(password, salt, block);

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
    key = convertPasswordToKey(password, salt, block);
  }

  // Concat all of the output chunks.
  const output = Buffer.concat(outputChunks);
  return output;
};
