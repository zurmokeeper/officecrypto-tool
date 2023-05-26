/* eslint-disable valid-jsdoc */
'use strict';

const CFB = require('cfb');
const common = require('./src/util/common');
const ecma376Standard = require('./crypto/ecma376_standard');


/**
 * @desc
 */
function decrypt() {
  const filename = '123456.xlsx';
  const cfb = CFB.read(filename, {type: 'file'});
  const encryptionInfo = CFB.find(cfb, '/EncryptionInfo');
  const EncryptedPackage = CFB.find(cfb, '/EncryptedPackage');
  const einfo = common.parseEncryptionInfo(encryptionInfo.content);
  const password = '';
  let output;

  if (einfo.type === 'standard') {
    const key = ecma376Standard.makeKeyFromPassword(password, algId, algIdHash, providerType, keySize, saltSize, salt);

    output = ecma376Standard.decrypt(key, EncryptedPackage.content);
  }

  if (einfo.type === 'agile') {
    const key = ecma376Standard.makeKeyFromPassword(password, algId, algIdHash, providerType, keySize, saltSize, salt);

    output = ecma376Standard.decrypt(key, EncryptedPackage.content);
  }

  if (einfo.type === 'extensible') {
    const key = ecma376Standard.makeKeyFromPassword(password, algId, algIdHash, providerType, keySize, saltSize, salt);

    output = ecma376Standard.decrypt(key, EncryptedPackage.content);
  }


  return output;
}


exports.decrypt = decrypt;
