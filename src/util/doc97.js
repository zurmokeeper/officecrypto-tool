/* eslint-disable valid-jsdoc */

const CFB = require('cfb');

const documentRC4 = require('../crypto/rc4');
const documentRC4CryptoAPI = require('../crypto/rc4_cryptoapi');

const getBit = (bits, i) => (bits & (1 << i)) >> i;
const getBitSlice = (bits, i, w) => (bits & ((2 ** w - 1) << i)) >> i;

const setBit = (bits, i, v) => (bits & ~(1 << i)) | (v << i);
const setBitSlice = (bits, i, w, v) => (bits & ~((2 ** w - 1) << i)) | ((v & (2 ** w - 1)) << i);

const parseFibBase = exports.parseFibBase = function parseFibBase(blob) {
  const wIdent = blob.read_shift(2);
  const nFib = blob.read_shift(2);
  const unused = blob.read_shift(2);
  const lid = blob.read_shift(2);
  const pnNext = blob.read_shift(2);

  const buffer1 = blob.read_shift(2);

  const fDot = getBit(buffer1, 0);
  const fGlsy = getBit(buffer1, 1);
  const fComplex = getBit(buffer1, 2);
  const fHasPic = getBit(buffer1, 3);
  const cQuickSaves = getBitSlice(buffer1, 4, 4);
  const fEncrypted = getBit(buffer1, 8);
  const fWhichTblStm = getBit(buffer1, 9);
  const fReadOnlyRecommended = getBit(buffer1, 10);
  const fWriteReservation = getBit(buffer1, 11);
  const fExtChar = getBit(buffer1, 12);
  const fLoadOverride = getBit(buffer1, 13);
  const fFarEast = getBit(buffer1, 14);
  const fObfuscation = getBit(buffer1, 15);

  const nFibBack = blob.read_shift(2);
  const IKey = blob.read_shift(4);
  const envr = blob.read_shift(1);
  const buffer2 = blob.read_shift(1);

  const fMac = getBit(buffer2, 0);
  const fEmptySpecial = getBit(buffer2, 1);
  const fLoadOverridePage = getBit(buffer2, 2);
  const reserved1 = getBit(buffer2, 3);
  const reserved2 = getBit(buffer2, 4);
  const fSpare0 = getBitSlice(buffer2, 5, 3);

  const reserved3 = blob.read_shift(2);
  const reserved4 = blob.read_shift(2);
  const reserved5 = blob.read_shift(4);
  const reserved6 = blob.read_shift(4);

  let tableName = '1Table';
  if (fWhichTblStm === 0) {
    tableName = '0Table';
  }

  const fibBase = {
    wIdent,
    nFib,
    unused,
    lid,
    pnNext,
    fDot,
    fGlsy,
    fComplex,
    fHasPic,
    cQuickSaves,
    fEncrypted,
    fWhichTblStm,
    fReadOnlyRecommended,
    fWriteReservation,
    fExtChar,
    fLoadOverride,
    fFarEast,
    fObfuscation,
    nFibBack,
    IKey,
    envr,
    fMac,
    fEmptySpecial,
    fLoadOverridePage,
    reserved1,
    reserved2,
    fSpare0,
    reserved3,
    reserved4,
    reserved5,
    reserved6,
    tableName,
  };
  return fibBase;
};


const buildFibBase = function buildFibBase(fibBase) {
  const blob = Buffer.alloc(32);
  CFB.utils.prep_blob(blob, 0);

  blob.write_shift(2, fibBase.wIdent);
  blob.write_shift(2, fibBase.nFib);
  blob.write_shift(2, fibBase.unused);
  blob.write_shift(2, fibBase.lid);
  blob.write_shift(2, fibBase.pnNext);
  let buf = 0xFFFF;

  buf = setBit(buf, 0, fibBase.fDot);
  buf = setBit(buf, 1, fibBase.fGlsy);
  buf = setBit(buf, 2, fibBase.fComplex);
  buf = setBit(buf, 3, fibBase.fHasPic);
  buf = setBitSlice(buf, 4, 4, fibBase.cQuickSaves);
  buf = setBit(buf, 8, fibBase.fEncrypted);
  buf = setBit(buf, 9, fibBase.fWhichTblStm);
  buf = setBit(buf, 10, fibBase.fReadOnlyRecommended);
  buf = setBit(buf, 11, fibBase.fWriteReservation);
  buf = setBit(buf, 12, fibBase.fExtChar);
  buf = setBit(buf, 13, fibBase.fLoadOverride);
  buf = setBit(buf, 14, fibBase.fFarEast);
  buf = setBit(buf, 15, fibBase.fObfuscation);
  blob.write_shift(2, buf);

  blob.write_shift(2, fibBase.nFibBack);
  blob.write_shift(4, fibBase.IKey);
  blob.write_shift(1, fibBase.envr);

  buf = 0xFF;
  buf = setBit(buf, 0, fibBase.fMac);
  buf = setBit(buf, 1, fibBase.fEmptySpecial);
  buf = setBit(buf, 2, fibBase.fLoadOverridePage);
  buf = setBit(buf, 3, fibBase.reserved1);
  buf = setBit(buf, 4, fibBase.reserved2);
  buf = setBitSlice(buf, 5, 3, fibBase.fSpare0);
  blob.write_shift(1, buf);

  blob.write_shift(2, fibBase.reserved3);
  blob.write_shift(2, fibBase.reserved4);
  blob.write_shift(4, fibBase.reserved5);
  blob.write_shift(4, fibBase.reserved6);

  return blob;
};

/**
 * @desc https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/76aeedb0-4d59-487f-8bd8-fb6860a60df7?redirectedfrom=MSDN
 */
function parseHeaderRC4(blob) {
  const data = {};
  const Salt = blob.slice(blob.l, blob.l + 16);
  data.Salt = Salt;
  blob.l = blob.l + 16;
  const EncryptedVerifier = blob.slice(blob.l, blob.l + 16);
  data.EncryptedVerifier = EncryptedVerifier;
  blob.l = blob.l + 16;
  const EncryptedVerifierHash = blob.slice(blob.l, blob.l + 16);
  data.EncryptedVerifierHash = EncryptedVerifierHash;
  return data;
}

/**
 * @desc
 */
function parseHeaderRC4CryptoAPI(blob, HeaderSize) {
  const length = blob.l + HeaderSize;
  const encryptionHeader = blob.slice(blob.l, length);
  const data = {};
  const Flags = blob.read_shift(4);
  data.Flags = Flags;
  const SizeExtra = blob.read_shift(4);
  data.SizeExtra = SizeExtra;
  const AlgID = blob.read_shift(4);
  data.AlgID = AlgID;
  const AlgIDHash = blob.read_shift(4);
  data.AlgIDHash = AlgIDHash;
  const KeySize = blob.read_shift(4);
  data.KeySize = KeySize;
  const ProviderType = blob.read_shift(4);
  data.ProviderType = ProviderType;
  const reserved1 = blob.read_shift(4);
  data.reserved1 = reserved1;
  const reserved2 = blob.read_shift(4);
  data.reserved2 = reserved2;
  const cspName = blob.read_shift(length - blob.l, 'utf16le');
  data.cspName = cspName;
  return data;
}

/**
 * @desc
 */
function parseRC4CryptoAPIEncryptionVerifier(blob) {
  const data = {};
  const saltSize = blob.read_shift(4);
  data.saltSize = saltSize;
  const Salt = blob.slice(blob.l, blob.l + 16);
  data.Salt = Salt;
  blob.l = blob.l + 16;
  const EncryptedVerifier = blob.slice(blob.l, blob.l + 16);
  data.EncryptedVerifier = EncryptedVerifier;
  blob.l = blob.l + 16;
  const VerifierHashSize = blob.read_shift(4);
  data.VerifierHashSize = VerifierHashSize;
  const EncryptedVerifierHash = blob.slice(blob.l, blob.l + VerifierHashSize);
  data.EncryptedVerifierHash = EncryptedVerifierHash;
  return data;
}

exports.decrypt = function decrypt(currCfb, blob, password, input) {
  if (!Buffer.isBuffer(blob)) blob = Buffer.from(blob);

  const fibBase = parseFibBase(blob);
  const fEncrypted = fibBase.fEncrypted;
  if (fEncrypted === 0) { // unencrypted
    return input; // Not encrypted returns directly to the original buffer
  }
  const fObfuscation = fibBase.fObfuscation;
  if (fObfuscation === 1) { // XOR obfuscation
    throw new Error('The XOR obfuscation algorithm is not supported at this time');
  }

  const tableName = fibBase.tableName;
  const TableWorkbook = CFB.find(currCfb, tableName);
  let tableBlob = TableWorkbook.content;
  if (!Buffer.isBuffer(tableBlob)) {
    tableBlob = Buffer.from(tableBlob);
    CFB.utils.prep_blob(tableBlob, 0);
  }
  const vMajor = tableBlob.read_shift(2);
  const vMinor = tableBlob.read_shift(2);
  const data = {};
  if (vMajor === 0x0001 && vMinor === 0x0001) { // RC4
    const info = parseHeaderRC4(tableBlob);
    const {Salt, EncryptedVerifier, EncryptedVerifierHash} = info;
    data.salt = Salt;
    data.type = 'rc4';
    const invalid = documentRC4.verifyPassword(password, Salt, EncryptedVerifier, EncryptedVerifierHash );
    if (!invalid) throw new Error('The password is incorrect');
  } else if ([0x0002, 0x0003, 0x0004].includes(vMajor) && vMinor === 0x0002) { // RC4 CryptoAPI
    const Flags = tableBlob.read_shift(4);
    const HeaderSize = tableBlob.read_shift(4);
    const info = parseHeaderRC4CryptoAPI(tableBlob, HeaderSize);
    const {KeySize} = info;
    const {Salt, EncryptedVerifier, EncryptedVerifierHash} = parseRC4CryptoAPIEncryptionVerifier(tableBlob);
    data.salt = Salt;
    data.type = 'rc4_crypto_api';
    data.keySize = KeySize;
    const invalid = documentRC4CryptoAPI.verifyPassword(password, Salt, KeySize, EncryptedVerifier, EncryptedVerifierHash );
    if (!invalid) throw new Error('The password is incorrect');
  } else {
    throw new Error('Unsupported encryption algorithms');
  }

  const output = rc4Decrypt(currCfb, blob, password, data, fibBase);
  return output;
};

/**
 * @desc
 */
function rc4Decrypt(currCfb, wordBlob, password, data, fibBase) {
  fibBase.fEncrypted = 0;
  fibBase.fObfuscation = 0;
  fibBase.IKey = 0;

  const newFibBase = buildFibBase(fibBase);
  const FIB_LENGTH = 0x44; // 68 bytes

  // The offset of wordBlob is already 32.  blob.l = 32
  const buffer = wordBlob.slice(wordBlob.l, FIB_LENGTH); // Get the 36 bytes.

  const encryptedBuf = wordBlob;
  const {salt, keySize, type} = data;
  let dec;
  if (type === 'rc4') {
    dec = documentRC4.decrypt(password, salt, encryptedBuf);
  } else {
    dec = documentRC4CryptoAPI.decrypt(password, salt, keySize, encryptedBuf);
  }
  // Discard the first 68 bytes of dec
  dec = dec.slice(FIB_LENGTH);

  const newWordDocumentBuffer = Buffer.concat([newFibBase, buffer, dec]);

  let tableDec;
  const tableName = fibBase.tableName;
  const TableWorkbook = CFB.find(currCfb, tableName);
  const tableEncryptedBuf = TableWorkbook.content;
  if (type === 'rc4') {
    tableDec = documentRC4.decrypt(password, salt, tableEncryptedBuf);
  } else {
    tableDec = documentRC4CryptoAPI.decrypt(password, salt, keySize, tableEncryptedBuf);
  }

  let dataDec;
  const DataWorkbook = CFB.find(currCfb, 'Data');
  if (DataWorkbook) {
    const dataEncryptedBuf = DataWorkbook.content;
    if (dataEncryptedBuf) {
      if (type === 'rc4') {
        dataDec = documentRC4.decrypt(password, salt, dataEncryptedBuf);
      } else {
        dataDec = documentRC4CryptoAPI.decrypt(password, salt, keySize, dataEncryptedBuf);
      }
    }
  }

  let output = CFB.utils.cfb_new();
  CFB.utils.cfb_add(output, 'WordDocument', newWordDocumentBuffer);
  CFB.utils.cfb_add(output, tableName, tableDec);

  if (DataWorkbook) {
    if (dataDec) {
      CFB.utils.cfb_add(output, 'Data', dataDec);
    } else {
      CFB.utils.cfb_add(output, 'Data', DataWorkbook.content);
    }
  }

  const CompObj = CFB.find(currCfb, '\u0001CompObj');
  if (CompObj) {
    CFB.utils.cfb_add(output, '\u0001CompObj', CompObj.content);
  }

  const SummaryInformation = CFB.find(currCfb, '\u0005SummaryInformation');
  if (SummaryInformation) {
    CFB.utils.cfb_add(output, '\u0005SummaryInformation', SummaryInformation.content);
  }

  const DocumentSummaryInformation = CFB.find(currCfb, '\u0005DocumentSummaryInformation');
  if (DocumentSummaryInformation) {
    CFB.utils.cfb_add(output, '\u0005DocumentSummaryInformation', DocumentSummaryInformation.content);
  }

  // Delete the SheetJS entry that is added at initialization
  CFB.utils.cfb_del(output, '\u0001Sh33tJ5');

  // Write to a buffer and return
  output = CFB.write(output);

  // The cfb library writes to a Uint8array in the browser. Convert to a Buffer.
  if (!Buffer.isBuffer(output)) output = Buffer.from(output);

  return output;
}
