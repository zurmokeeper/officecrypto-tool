/* eslint-disable valid-jsdoc */


const crypto = require('crypto');

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

exports.verifyPassword = function verifyPw(password, salt, encryptedVerifier, encryptedVerifierHash) {
  const block = 0;
  const key = convertPasswordToKey(password, salt, block);
  const cipher = crypto.createDecipheriv('rc4', key, '');
  const verifier = Buffer.concat([cipher.update(encryptedVerifier)]);

  const hash = crypto.createHash('md5').update(verifier).digest();

  const verifierHash = Buffer.concat([cipher.update(encryptedVerifierHash), cipher.final()]);

  return verifierHash.equals(hash);
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

    // Encrypt/decrypt the chunk and add it to the array
    const cipher = crypto.createDecipheriv('rc4', key, '');
    const outputChunk = Buffer.concat([cipher.update(inputChunk), cipher.final()]);
    outputChunks.push(outputChunk);

    block += 1;
    key = convertPasswordToKey(password, salt, block);
  }

  // Concat all of the output chunks.
  const output = Buffer.concat(outputChunks);
  return output;
};
