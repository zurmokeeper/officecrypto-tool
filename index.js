/* eslint-disable valid-jsdoc */
'use strict';

const CFB = require('cfb');
const common = require('./src/util/common');
const ecma376Standard = require('./src/crypto/ecma376_standard');
const ecma376Agile = require('./src/crypto/ecma376_agile');


/**
 * @desc
 */
async function decrypt(input, options) {
  if (!Buffer.isBuffer(input)) throw new Error('The input must be a buffer');
  if (!options || !options.password) throw new Error('options.password is required');

  const cfb = CFB.read(input, {type: 'buffer'});
  const encryptionInfo = CFB.find(cfb, '/EncryptionInfo');

  if (encryptionInfo) { // 这个是xlsx格式的加密
    const encryptedPackage = CFB.find(cfb, '/EncryptedPackage');
    const einfo = common.parseEncryptionInfo(encryptionInfo.content);
    const password = options.password;
    let output;

    if (einfo.type === 'standard') {
      const {Flags, AlgID, AlgIDHash, KeySize, ProviderType} = einfo.h;
      const {Salt, Verifier, VerifierHash} = einfo.v;
      const saltSize = 16;

      const key = ecma376Standard.convertPasswordToKey(password, AlgID, AlgIDHash, ProviderType, KeySize, saltSize, Salt);

      const valid = ecma376Standard.verifyKey(key, Verifier, VerifierHash);
      if (!valid) throw new Error('The password is incorrect');

      output = ecma376Standard.decrypt(key, encryptedPackage.content);
    }

    if (einfo.type === 'agile') {
      const data = {
        encryptionInfoBuffer: encryptionInfo.content,
        encryptedPackageBuffer: encryptedPackage.content,
      };
      output = await ecma376Agile.decrypt(data, password);
    }

    if (einfo.type === 'extensible') {
      throw new Error('Unsupported encryption algorithms');
    }
    return output;
  }

  throw new Error('Unsupported encryption algorithms');
}

/**
 *
 * @param {*} input
 * @param {*} options
 * @returns
 */
async function encrypt(input, options) {
  if (!Buffer.isBuffer(input)) throw new Error('The input must be a buffer');
  if (!options || !options.password) throw new Error('options.password is required');

  const cfb = CFB.read(input, {type: 'buffer'});
  const encryptionInfo = CFB.find(cfb, '/EncryptionInfo');

  if (encryptionInfo) { // 这个是xlsx格式的加密
    const encryptedPackage = CFB.find(cfb, '/EncryptedPackage');
    const einfo = common.parseEncryptionInfo(encryptionInfo.content);
    const password = options.password;
    let output;

    if (einfo.type === 'standard') {
      const {Flags, AlgID, AlgIDHash, KeySize, ProviderType} = einfo.h;
      const {Salt, Verifier, VerifierHash} = einfo.v;
      const saltSize = 16;

      const key = ecma376Standard.convertPasswordToKey(password, AlgID, AlgIDHash, ProviderType, KeySize, saltSize, Salt);

      const valid = ecma376Standard.verifyKey(key, Verifier, VerifierHash);
      if (!valid) throw new Error('The password is incorrect');

      output = ecma376Standard.decrypt(key, encryptedPackage.content);
    }

    if (einfo.type === 'agile') {
      const data = {
        encryptionInfoBuffer: encryptionInfo.content,
        encryptedPackageBuffer: encryptedPackage.content,
      };
      output = await ecma376Agile.decrypt(data, password);
    }

    if (einfo.type === 'extensible') {
      throw new Error('Unsupported encryption algorithms');
    }
    return output;
  }

  throw new Error('Unsupported encryption algorithms');
}


exports.decrypt = decrypt;
exports.encrypt = encrypt;
