/* eslint-disable valid-jsdoc */
'use strict';

const CFB = require('cfb');
const common = require('./src/util/common');
const ecma376Standard = require('./src/crypto/ecma376_standard');
const ecma376Agile = require('./src/crypto/ecma376_agile');

const xls97File = require('./src/util/xls97');
const doc97File = require('./src/util/doc97');
const ppt97File = require('./src/util/ppt97');

/**
 *
 * @param {*} input
 * @param {*} options
 * @returns
 */
async function decrypt(input, options) {
  if (!Buffer.isBuffer(input)) {
    // This is an ArrayBuffer in the browser. Convert to a Buffer.
    if (ArrayBuffer.isView(input) || input instanceof ArrayBuffer) {
      input = Buffer.from(input);
    } else {
      throw new Error('The input must be a buffer');
    }
  }
  if (!options || !options.password) throw new Error('options.password is required');

  const cfb = CFB.read(input, {type: 'buffer'});
  const encryptionInfo = CFB.find(cfb, '/EncryptionInfo');
  const password = options.password;
  let output;

  if (encryptionInfo) { // This is encrypted in xlsx format
    const encryptedPackage = CFB.find(cfb, '/EncryptedPackage');
    const einfo = common.parseEncryptionInfo(encryptionInfo.content);

    if (einfo.type === 'standard') {
      const {Flags, AlgID, AlgIDHash, KeySize, ProviderType} = einfo.h;
      const {Salt, Verifier, VerifierHash} = einfo.v;
      const saltSize = 16;

      const key = ecma376Standard.convertPasswordToKey(password, AlgID, AlgIDHash, ProviderType, KeySize, saltSize, Salt);

      const valid = ecma376Standard.verifyKey(key, Verifier, VerifierHash);
      if (!valid) throw new Error('The password is incorrect');

      output = ecma376Standard.decrypt(key, encryptedPackage.content);
      return output;
    }

    if (einfo.type === 'agile') {
      const data = {
        encryptionInfoBuffer: encryptionInfo.content,
        encryptedPackageBuffer: encryptedPackage.content,
      };
      output = await ecma376Agile.decrypt(data, password);
      return output;
    }

    if (einfo.type === 'extensible') {
    }
    throw new Error('Unsupported encryption algorithms');
  }

  const Workbook = CFB.find(cfb, 'Workbook');
  if (Workbook) {
    output = xls97File.decrypt(cfb, Workbook.content, password, input);
    return output;
  }

  const WordWorkbook = CFB.find(cfb, 'wordDocument');
  if (WordWorkbook) {
    output = doc97File.decrypt(cfb, WordWorkbook.content, password, input);
    return output;
  }

  const PowerPointBook = CFB.find(cfb, 'PowerPoint Document');
  if (PowerPointBook) {
    output = ppt97File.decrypt(cfb, PowerPointBook.content, password, input);
    return output;
  }

  if (!encryptionInfo) return input; // Not encrypted returns directly to the original buffer

  throw new Error('Unsupported encryption algorithms');
}

/**
 *
 * @param {*} input
 * @param {*} options
 * @returns
 */
function encrypt(input, options) {
  if (!Buffer.isBuffer(input)) {
    // This is an ArrayBuffer in the browser. Convert to a Buffer.
    if (ArrayBuffer.isView(input) || input instanceof ArrayBuffer) {
      input = Buffer.from(input);
    } else {
      throw new Error('The input must be a buffer');
    }
  }
  if (!options || !options.password) throw new Error('options.password is required');

  const maxFieldLength = 255;
  if (options.password.length > maxFieldLength) throw new Error(`The maximum password length is ${maxFieldLength}`);
  let output;

  if (options.hasOwnProperty('type') && !['standard'].includes(options.type)) {
    throw new Error(`options.type must be ['standard']`);
  }
  if (options.type === 'standard') {
    output = ecma376Standard.encryptStandard(input, options.password);
  } else {
    output = ecma376Agile.encrypt(input, options.password);
  }
  return output;
}

/**
 *
 * @param {*} input
 * @returns
 */
function isEncrypted(input) {
  if (!Buffer.isBuffer(input)) {
    // This is an ArrayBuffer in the browser. Convert to a Buffer.
    if (ArrayBuffer.isView(input) || input instanceof ArrayBuffer) {
      input = Buffer.from(input);
    } else {
      throw new Error('The input must be a buffer');
    }
  }
  const cfb = CFB.read(input, {type: 'buffer'});
  const encryptionInfo = CFB.find(cfb, '/EncryptionInfo');
  if (encryptionInfo) return true;
  const Workbook = CFB.find(cfb, 'Workbook');
  if (Workbook) {
    let blob = Workbook.content;
    if (!Buffer.isBuffer(blob)) blob = Buffer.from(blob);
    const bof = blob.read_shift(2);
    const bofSize = blob.read_shift(2);
    blob.l = blob.l + bofSize; // -> skip BOF record
    const filePass = blob.read_shift(2);
    if (filePass === 47) { // 'FilePass': 47,
      return true;
    }
  }

  const WordDocument = CFB.find(cfb, 'wordDocument');
  if (WordDocument) {
    let blob = WordDocument.content;
    if (!Buffer.isBuffer(blob)) blob = Buffer.from(blob);
    const fibBase = doc97File.parseFibBase(blob);
    const fEncrypted = fibBase.fEncrypted;
    if (fEncrypted === 1) {
      return true;
    }
  }

  const PowerPointBook = CFB.find(cfb, 'PowerPoint Document');
  if (PowerPointBook) {
    let blob = PowerPointBook.content;
    if (!Buffer.isBuffer(blob)) blob = Buffer.from(blob);

    const CurrentUser = CFB.find(cfb, 'Current User');
    let currentUserBlob = CurrentUser.content;
    if (!Buffer.isBuffer(currentUserBlob)) currentUserBlob = Buffer.from(currentUserBlob);

    const currentUser = ppt97File.parseCurrentUser(currentUserBlob);
    blob.l = currentUser.currentUserAtom.offsetToCurrentEdit;
    const userEditAtom = ppt97File.parseUserEditAtom(blob);
    if (userEditAtom.rh.recLen === 0x00000020) {
      return true;
    }
  }

  return false;
}

exports.decrypt = decrypt;
exports.encrypt = encrypt;
exports.isEncrypted = isEncrypted;
