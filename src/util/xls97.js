/* eslint-disable valid-jsdoc */

const CFB = require('cfb');
const crypto = require('crypto');
const CryptoJS = require('crypto-js');

const documentRC4 = require('../crypto/rc4');
const documentRC4CryptoAPI = require('../crypto/rc4_cryptoapi');
const documentXOR = require('../crypto/xor_obfuscation');

const recordNameNum = {
  'Formula': 6,
  'EOF': 10,
  'CalcCount': 12,
  'CalcMode': 13,
  'CalcPrecision': 14,
  'CalcRefMode': 15,
  'CalcDelta': 16,
  'CalcIter': 17,
  'Protect': 18,
  'Password': 19,
  'Header': 20,
  'Footer': 21,
  'ExternSheet': 23,
  'Lbl': 24,
  'WinProtect': 25,
  'VerticalPageBreaks': 26,
  'HorizontalPageBreaks': 27,
  'Note': 28,
  'Selection': 29,
  'Date1904': 34,
  'ExternName': 35,
  'LeftMargin': 38,
  'RightMargin': 39,
  'TopMargin': 40,
  'BottomMargin': 41,
  'PrintRowCol': 42,
  'PrintGrid': 43,
  'FilePass': 47,
  'Font': 49,
  'PrintSize': 51,
  'Continue': 60,
  'Window1': 61,
  'Backup': 64,
  'Pane': 65,
  'CodePage': 66,
  'Pls': 77,
  'DCon': 80,
  'DConRef': 81,
  'DConName': 82,
  'DefColWidth': 85,
  'XCT': 89,
  'CRN': 90,
  'FileSharing': 91,
  'WriteAccess': 92,
  'Obj': 93,
  'Uncalced': 94,
  'CalcSaveRecalc': 95,
  'Template': 96,
  'Intl': 97,
  'ObjProtect': 99,
  'ColInfo': 125,
  'Guts': 128,
  'WsBool': 129,
  'GridSet': 130,
  'HCenter': 131,
  'VCenter': 132,
  'BoundSheet8': 133,
  'WriteProtect': 134,
  'Country': 140,
  'HideObj': 141,
  'Sort': 144,
  'Palette': 146,
  'Sync': 151,
  'LPr': 152,
  'DxGCol': 153,
  'FnGroupName': 154,
  'FilterMode': 155,
  'BuiltInFnGroupCount': 156,
  'AutoFilterInfo': 157,
  'AutoFilter': 158,
  'Scl': 160,
  'Setup': 161,
  'ScenMan': 174,
  'SCENARIO': 175,
  'SxView': 176,
  'Sxvd': 177,
  'SXVI': 178,
  'SxIvd': 180,
  'SXLI': 181,
  'SXPI': 182,
  'DocRoute': 184,
  'RecipName': 185,
  'MulRk': 189,
  'MulBlank': 190,
  'Mms': 193,
  'SXDI': 197,
  'SXDB': 198,
  'SXFDB': 199,
  'SXDBB': 200,
  'SXNum': 201,
  'SxBool': 202,
  'SxErr': 203,
  'SXInt': 204,
  'SXString': 205,
  'SXDtr': 206,
  'SxNil': 207,
  'SXTbl': 208,
  'SXTBRGIITM': 209,
  'SxTbpg': 210,
  'ObProj': 211,
  'SXStreamID': 213,
  'DBCell': 215,
  'SXRng': 216,
  'SxIsxoper': 217,
  'BookBool': 218,
  'DbOrParamQry': 220,
  'ScenarioProtect': 221,
  'OleObjectSize': 222,
  'XF': 224,
  'InterfaceHdr': 225,
  'InterfaceEnd': 226,
  'SXVS': 227,
  'MergeCells': 229,
  'BkHim': 233,
  'MsoDrawingGroup': 235,
  'MsoDrawing': 236,
  'MsoDrawingSelection': 237,
  'PhoneticInfo': 239,
  'SxRule': 240,
  'SXEx': 241,
  'SxFilt': 242,
  'SxDXF': 244,
  'SxItm': 245,
  'SxName': 246,
  'SxSelect': 247,
  'SXPair': 248,
  'SxFmla': 249,
  'SxFormat': 251,
  'SST': 252,
  'LabelSst': 253,
  'ExtSST': 255,
  'SXVDEx': 256,
  'SXFormula': 259,
  'SXDBEx': 290,
  'RRDInsDel': 311,
  'RRDHead': 312,
  'RRDChgCell': 315,
  'RRTabId': 317,
  'RRDRenSheet': 318,
  'RRSort': 319,
  'RRDMove': 320,
  'RRFormat': 330,
  'RRAutoFmt': 331,
  'RRInsertSh': 333,
  'RRDMoveBegin': 334,
  'RRDMoveEnd': 335,
  'RRDInsDelBegin': 336,
  'RRDInsDelEnd': 337,
  'RRDConflict': 338,
  'RRDDefName': 339,
  'RRDRstEtxp': 340,
  'LRng': 351,
  'UsesELFs': 352,
  'DSF': 353,
  'CUsr': 401,
  'CbUsr': 402,
  'UsrInfo': 403,
  'UsrExcl': 404,
  'FileLock': 405,
  'RRDInfo': 406,
  'BCUsrs': 407,
  'UsrChk': 408,
  'UserBView': 425,
  'UserSViewBegin': 426,
  'UserSViewBegin_Chart': 426,
  'UserSViewEnd': 427,
  'RRDUserView': 428,
  'Qsi': 429,
  'SupBook': 430,
  'Prot4Rev': 431,
  'CondFmt': 432,
  'CF': 433,
  'DVal': 434,
  'DConBin': 437,
  'TxO': 438,
  'RefreshAll': 439,
  'HLink': 440,
  'Lel': 441,
  'CodeName': 442,
  'SXFDBType': 443,
  'Prot4RevPass': 444,
  'ObNoMacros': 445,
  'Dv': 446,
  'Excel9File': 448,
  'RecalcId': 449,
  'EntExU2': 450,
  'Dimensions': 512,
  'Blank': 513,
  'Number': 515,
  'Label': 516,
  'BoolErr': 517,
  'String': 519,
  'Row': 520,
  'Index': 523,
  'Array': 545,
  'DefaultRowHeight': 549,
  'Table': 566,
  'Window2': 574,
  'RK': 638,
  'Style': 659,
  'BigName': 1048,
  'Format': 1054,
  'ContinueBigName': 1084,
  'ShrFmla': 1212,
  'HLinkTooltip': 2048,
  'WebPub': 2049,
  'QsiSXTag': 2050,
  'DBQueryExt': 2051,
  'ExtString': 2052,
  'TxtQry': 2053,
  'Qsir': 2054,
  'Qsif': 2055,
  'RRDTQSIF': 2056,
  'BOF': 2057,
  'OleDbConn': 2058,
  'WOpt': 2059,
  'SXViewEx': 2060,
  'SXTH': 2061,
  'SXPIEx': 2062,
  'SXVDTEx': 2063,
  'SXViewEx9': 2064,
  'ContinueFrt': 2066,
  'RealTimeData': 2067,
  'ChartFrtInfo': 2128,
  'FrtWrapper': 2129,
  'StartBlock': 2130,
  'EndBlock': 2131,
  'StartObject': 2132,
  'EndObject': 2133,
  'CatLab': 2134,
  'YMult': 2135,
  'SXViewLink': 2136,
  'PivotChartBits': 2137,
  'FrtFontList': 2138,
  'SheetExt': 2146,
  'BookExt': 2147,
  'SXAddl': 2148,
  'CrErr': 2149,
  'HFPicture': 2150,
  'FeatHdr': 2151,
  'Feat': 2152,
  'DataLabExt': 2154,
  'DataLabExtContents': 2155,
  'CellWatch': 2156,
  'FeatHdr11': 2161,
  'Feature11': 2162,
  'DropDownObjIds': 2164,
  'ContinueFrt11': 2165,
  'DConn': 2166,
  'List12': 2167,
  'Feature12': 2168,
  'CondFmt12': 2169,
  'CF12': 2170,
  'CFEx': 2171,
  'XFCRC': 2172,
  'XFExt': 2173,
  'AutoFilter12': 2174,
  'ContinueFrt12': 2175,
  'MDTInfo': 2180,
  'MDXStr': 2181,
  'MDXTuple': 2182,
  'MDXSet': 2183,
  'MDXProp': 2184,
  'MDXKPI': 2185,
  'MDB': 2186,
  'PLV': 2187,
  'Compat12': 2188,
  'DXF': 2189,
  'TableStyles': 2190,
  'TableStyle': 2191,
  'TableStyleElement': 2192,
  'StyleExt': 2194,
  'NamePublish': 2195,
  'NameCmt': 2196,
  'SortData': 2197,
  'Theme': 2198,
  'GUIDTypeLib': 2199,
  'FnGrp12': 2200,
  'NameFnGrp12': 2201,
  'MTRSettings': 2202,
  'CompressPictures': 2203,
  'HeaderFooter': 2204,
  'CrtLayout12': 2205,
  'CrtMlFrt': 2206,
  'CrtMlFrtContinue': 2207,
  'ForceFullCalculation': 2211,
  'ShapePropsStream': 2212,
  'TextPropsStream': 2213,
  'RichTextStream': 2214,
  'CrtLayout12A': 2215,
  'Units': 4097,
  'Chart': 4098,
  'Series': 4099,
  'DataFormat': 4102,
  'LineFormat': 4103,
  'MarkerFormat': 4105,
  'AreaFormat': 4106,
  'PieFormat': 4107,
  'AttachedLabel': 4108,
  'SeriesText': 4109,
  'ChartFormat': 4116,
  'Legend': 4117,
  'SeriesList': 4118,
  'Bar': 4119,
  'Line': 4120,
  'Pie': 4121,
  'Area': 4122,
  'Scatter': 4123,
  'CrtLine': 4124,
  'Axis': 4125,
  'Tick': 4126,
  'ValueRange': 4127,
  'CatSerRange': 4128,
  'AxisLine': 4129,
  'CrtLink': 4130,
  'DefaultText': 4132,
  'Text': 4133,
  'FontX': 4134,
  'ObjectLink': 4135,
  'Frame': 4146,
  'Begin': 4147,
  'End': 4148,
  'PlotArea': 4149,
  'Chart3d': 4154,
  'PicF': 4156,
  'DropBar': 4157,
  'Radar': 4158,
  'Surf': 4159,
  'RadarArea': 4160,
  'AxisParent': 4161,
  'LegendException': 4163,
  'ShtProps': 4164,
  'SerToCrt': 4165,
  'AxesUsed': 4166,
  'SBaseRef': 4168,
  'SerParent': 4170,
  'SerAuxTrend': 4171,
  'IFmtRecord': 4174,
  'Pos': 4175,
  'AlRuns': 4176,
  'BRAI': 4177,
  'SerAuxErrBar': 4187,
  'ClrtClient': 4188,
  'SerFmt': 4189,
  'Chart3DBarShape': 4191,
  'Fbi': 4192,
  'BopPop': 4193,
  'AxcExt': 4194,
  'Dat': 4195,
  'PlotGrowth': 4196,
  'SIIndex': 4197,
  'GelFrame': 4198,
  'BopPopCustom': 4199,
  'Fbi2': 4200,
};

/**
 * @desc [num, size, record]
 */
function iterRecord(blob) {
  const dataList = [];
  while (true) {
    const h = blob.read_shift(4);
    if (!h) {
      break;
    }
    blob.l = blob.l - 4; // 重置偏移量
    const l = blob.l;
    const header = blob.slice(blob.l, blob.l + 4);
    const num = blob.read_shift(2);
    const size = blob.read_shift(2);
    const record = blob.slice(blob.l, blob.l + size);
    // const temp = {header, num, size, record};
    const temp = {header, num, size, record, l};
    if (num === recordNameNum.Font && dataList.length === 44) {
      
    } else {
      dataList.push(temp);
    }
    // dataList.push(temp);
    blob.l = blob.l + size;
  }
  return dataList;
}

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
  const bof = blob.read_shift(2);
  const bofSize = blob.read_shift(2);
  const vers = blob.read_shift(2); // 0x0006 -> BIFF8  0x0005 ->BIFF5/7
  blob.l = blob.l - 2;
  blob.l = blob.l + bofSize; // -> skip BOF record

  // FilePass: https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/cf9ae8d5-4e8c-40a2-95f1-3b31f16b5529?redirectedfrom=MSDN
  // If this record exists, the workbook MUST be encrypted.

  const record = blob.read_shift(2);
  let filePass = record;
  if (record === 134) { // 'WriteProtect': 134
    // Skip if record is WriteProtect
    const writeProtectSize = blob.read_shift(2);
    filePass = blob.read_shift(2);
  }

  if (filePass !== 47) { // 'FilePass': 47,
    return input; // Not encrypted returns directly to the original buffer
  }
  const filePassSize = blob.read_shift(2);
  const wEncryptionType = blob.read_shift(2);

  const data = {};

  if (wEncryptionType === 0x0000) { // XOR obfuscation
    const key = blob.read_shift(2);
    const verificationBytes = blob.read_shift(2);
    // console.log('key-->', key, verificationBytes);
    const invalid = documentXOR.verifyPassword(password, verificationBytes);
    if (!invalid) throw new Error('The password is incorrect');
    const output = rc4Decrypt(currCfb, blob, password, data);
    return output;
  }
  if (wEncryptionType !== 0x0001) { // 0x0001 rc4
    throw new Error('Unsupported encryption algorithms');
  }

  const vMajor = blob.read_shift(2);
  const vMinor = blob.read_shift(2);

  if (vMajor === 0x0001 && vMinor === 0x0001) { // RC4
    const info = parseHeaderRC4(blob);
    const {Salt, EncryptedVerifier, EncryptedVerifierHash} = info;
    data.salt = Salt;
    data.type = 'rc4';
    const invalid = documentRC4.verifyPassword(password, Salt, EncryptedVerifier, EncryptedVerifierHash );
    if (!invalid) throw new Error('The password is incorrect');
  } else if ([0x0002, 0x0003, 0x0004].includes(vMajor) && vMinor === 0x0002) { // RC4 CryptoAPI
    const Flags = blob.read_shift(4);
    const HeaderSize = blob.read_shift(4);
    const info = parseHeaderRC4CryptoAPI(blob, HeaderSize);
    const {KeySize} = info;
    const {Salt, EncryptedVerifier, EncryptedVerifierHash} = parseRC4CryptoAPIEncryptionVerifier(blob);
    data.salt = Salt;
    data.type = 'rc4_crypto_api';
    data.keySize = KeySize;
    const invalid = documentRC4CryptoAPI.verifyPassword(password, Salt, KeySize, EncryptedVerifier, EncryptedVerifierHash );
    if (!invalid) throw new Error('The password is incorrect');
  } else {
    throw new Error('Unsupported encryption algorithms');
  }

  const output = rc4Decrypt(currCfb, blob, password, data);
  return output;
};

/**
 * @desc
 */
function rc4Decrypt(currCfb, blob, password, data) {
  const plainBuf = [];
  let encryptedBuf = [];
  blob.l = 0; // Reset Offset
  const dataList = iterRecord(blob);

  // header [num, size] 2 bytes each
  for (const {header, num, size, record} of dataList) {
    // Remove encryption, pad by zero to preserve stream size
    if (num === recordNameNum.FilePass) {
      // header.slice(2); // size
      plainBuf.push(0, 0, ...header.slice(2), ...Array(size).fill(0));
      encryptedBuf.push(Buffer.alloc(4 + size));
    //   The following records MUST NOT be obfuscated or encrypted: BOF (section 2.4.21),
    //   FilePass (section 2.4.117), UsrExcl (section 2.4.339), FileLock (section 2.4.116),
    //   InterfaceHdr (section 2.4.146), RRDInfo (section 2.4.227), and RRDHead (section 2.4.226).
    } else if ([
      recordNameNum.BOF,
      recordNameNum.FilePass,
      recordNameNum.UsrExcl,
      recordNameNum.FileLock,
      recordNameNum.InterfaceHdr,
      recordNameNum.RRDInfo,
      recordNameNum.RRDHead,
    ].includes(num)) {
      plainBuf.push(...header, ...record);
      encryptedBuf.push(Buffer.alloc(4 + size));
    // The lbPlyPos field of the BoundSheet8 record (section 2.4.28) MUST NOT be encrypted.
    } else if (num === recordNameNum.BoundSheet8) {
      const lbPlyPos = record.slice(0, 4);
      const restSize = size - 4;
      // plainBuf.push(...header, ...lbPlyPos, ...Array(restSize).fill(-1));
      plainBuf.push(...header, ...lbPlyPos, ...Array(restSize).fill(-2));
      encryptedBuf.push(Buffer.concat([Buffer.alloc(4), Buffer.alloc(4), record.slice(4)]));
    } else {
      plainBuf.push(...header, ...Array(size).fill(-1));
      encryptedBuf.push(Buffer.concat([Buffer.alloc(4), record]));
    }
  }

  encryptedBuf = Buffer.concat(encryptedBuf);

  const {salt, keySize, type} = data;
  let dec;
  const blocksize = 1024;
  if (type === 'rc4') {
    dec = documentRC4.decrypt(password, salt, encryptedBuf, blocksize);
  } else if (type === 'rc4_crypto_api') {
    dec = documentRC4CryptoAPI.decrypt(password, salt, keySize, encryptedBuf, blocksize);
  } else {
    dec = documentXOR.decrypt(password, encryptedBuf, plainBuf);
  }

  for (let i = 0; i < plainBuf.length; i++) {
    const c = plainBuf[i];
    if (c !== -1 && c !== -2) {
      dec.writeUInt8(c, i);
    }
  }

  let output = CFB.utils.cfb_new();
  CFB.utils.cfb_add(output, 'Workbook', dec);

  const ETExtData = CFB.find(currCfb, 'ETExtData');
  if (ETExtData) {
    CFB.utils.cfb_add(output, 'ETExtData', ETExtData.content);
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


/**
 * @desc Only node.js is supported.
 */
// function buildHeaderRC4(password) {
//   const salt = crypto.randomBytes(16);

//   const block = 0;
//   const key = documentRC4.convertPasswordToKey(password, salt, block);

//   const encryptedVerifier = crypto.randomBytes(16);
//   const encryptedVerifierHash = crypto.createHash('md5').update(encryptedVerifier).digest();

//   const cipher = crypto.createCipheriv('rc4', key, '');
//   const EncryptedVerifier = Buffer.concat([cipher.update(encryptedVerifier)]);
//   const EncryptedVerifierHash = Buffer.concat([cipher.update(encryptedVerifierHash), cipher.final()]);

//   return {Salt: salt, EncryptedVerifier, EncryptedVerifierHash};
// }

/**
 * @desc Because crypto's front-end compatibility library, crypto-browserify, does not support the rc4 algorithm,
 * we have switched to crypto-js to handle the rc4 algorithm for both node.js and the browser side.
 * @returns
 */
function buildHeaderRC4(password) {
  const salt = crypto.randomBytes(16);

  const block = 0;
  const key = documentRC4.convertPasswordToKey(password, salt, block);

  const encryptedVerifier = crypto.randomBytes(16);
  const encryptedVerifierHash = crypto.createHash('md5').update(encryptedVerifier).digest();

  const cipher = CryptoJS.algo.RC4.createEncryptor(CryptoJS.lib.WordArray.create(key));
  let EncryptedVerifier = cipher.finalize(CryptoJS.lib.WordArray.create(encryptedVerifier));
  let EncryptedVerifierHash = cipher.finalize(CryptoJS.lib.WordArray.create(encryptedVerifierHash));

  EncryptedVerifier = EncryptedVerifier.toString(CryptoJS.enc.Hex);
  EncryptedVerifierHash = EncryptedVerifierHash.toString(CryptoJS.enc.Hex);

  return {Salt: salt, EncryptedVerifier, EncryptedVerifierHash};
}

/**
 * @desc
 */
function buildHeaderRC4CryptoAPI(headerSize) {
  const blob = Buffer.alloc(headerSize);
  CFB.utils.prep_blob(blob, 0);
  blob.write_shift(4, 0x0000000c); // Flags
  blob.write_shift(4, 0x0); // SizeExtra
  blob.write_shift(4, 0x00006801); // AlgID
  blob.write_shift(4, 0x00008004); // AlgIDHash
  const KeySize = 0x00000080;
  blob.write_shift(4, KeySize); // KeySize
  blob.write_shift(4, 0x00000001); // ProviderType
  blob.write_shift(4, 0x0); // reserved1
  blob.write_shift(4, 0x0); // reserved2

  const cspName = 'Microsoft Enhanced Cryptographic Provider v1.0 (Prototype)';
  blob.write_shift(headerSize - 32, cspName, 'utf16le'); // cspName  TODO:

  return {blob, KeySize};
}


/**
 * @desc
 */
// function buildRC4CryptoAPIEncryptionVerifier(options, size, keySize, block = 0) {
//   const blob = Buffer.alloc(size);
//   CFB.utils.prep_blob(blob, 0);

//   const salt = crypto.randomBytes(16);
//   const key = documentRC4CryptoAPI.convertPasswordToKey(options.password, salt, keySize, block);

//   const encryptedVerifier = crypto.randomBytes(16);
//   const encryptedVerifierHash = crypto.createHash('sha1').update(encryptedVerifier).digest();

//   const cipher = crypto.createCipheriv('rc4', key, '');
//   const EncryptedVerifier = Buffer.concat([cipher.update(encryptedVerifier)]);
//   const EncryptedVerifierHash = Buffer.concat([cipher.update(encryptedVerifierHash), cipher.final()]);

//   blob.write_shift(4, 0x10); // saltSize
//   blob.write_shift(16, salt.toString('hex'), 'hex'); // Salt
//   blob.write_shift(16, EncryptedVerifier.toString('hex'), 'hex'); // EncryptedVerifier
//   blob.write_shift(4, size - 40); // VerifierHashSize
//   blob.write_shift(size - 40, EncryptedVerifierHash.toString('hex'), 'hex'); // EncryptedVerifierHash  20 Byte
//   return {blob, Salt: salt};
// }

/**
 * @desc
 */
function buildRC4CryptoAPIEncryptionVerifier(options, size, keySize, block = 0) {
  const blob = Buffer.alloc(size);
  CFB.utils.prep_blob(blob, 0);

  const salt = crypto.randomBytes(16);
  const key = documentRC4CryptoAPI.convertPasswordToKey(options.password, salt, keySize, block);

  const encryptedVerifier = crypto.randomBytes(16);
  const encryptedVerifierHash = crypto.createHash('sha1').update(encryptedVerifier).digest();

  const cipher = CryptoJS.algo.RC4.createEncryptor(CryptoJS.lib.WordArray.create(key));
  let EncryptedVerifier = cipher.finalize(CryptoJS.lib.WordArray.create(encryptedVerifier));
  let EncryptedVerifierHash = cipher.finalize(CryptoJS.lib.WordArray.create(encryptedVerifierHash));

  EncryptedVerifier = EncryptedVerifier.toString(CryptoJS.enc.Hex);
  EncryptedVerifierHash = EncryptedVerifierHash.toString(CryptoJS.enc.Hex);

  // EncryptedVerifier = Buffer.from(EncryptedVerifier, 'hex');
  // EncryptedVerifierHash = Buffer.from(EncryptedVerifierHash, 'hex');

  blob.write_shift(4, 0x10); // saltSize
  blob.write_shift(16, salt.toString('hex'), 'hex'); // Salt
  // blob.write_shift(16, EncryptedVerifier.toString('hex'), 'hex'); // EncryptedVerifier
  blob.write_shift(16, EncryptedVerifier, 'hex'); // EncryptedVerifier
  blob.write_shift(4, size - 40); // VerifierHashSize
  // blob.write_shift(size - 40, EncryptedVerifierHash.toString('hex'), 'hex'); // EncryptedVerifierHash  20 Byte
  blob.write_shift(size - 40, EncryptedVerifierHash, 'hex'); // EncryptedVerifierHash  20 Byte
  return {blob, Salt: salt};
}


/**
 * @desc
 */
function buildWorkbookInfo3(cfb, blob, options) {
  const {password, type} = options;
  if (!Buffer.isBuffer(blob)) blob = Buffer.from(blob);

  const bof = blob.read_shift(2);
  const bofSize = blob.read_shift(2);
  blob.l = blob.l + bofSize; // -> skip BOF record

  let filePassRecordLength = 0;
  switch (type) {
    case 'rc4':
      filePassRecordLength = 2 + 2 + 54; // 58Byte
      break;
    case 'rc4_crypto_api':
      filePassRecordLength = 2 + 2 + 200; // 204Byte
      break;
    default:
      break;
  }

  const newBlob = Buffer.alloc(blob.byteLength + filePassRecordLength);
  CFB.utils.prep_blob(newBlob, 0);

  blob.copy(newBlob, 0, 0, blob.l);

  newBlob.l = blob.l;
  newBlob.write_shift(2, 0x002f); // FilePass

  const data = {};
  switch (type) {
    case 'rc4':
      newBlob.write_shift(2, 0x0036); // FilePass size (54 Byte)
      newBlob.write_shift(2, 0x0001); // wEncryptionType
      newBlob.write_shift(2, 0x0001); // vMajor
      newBlob.write_shift(2, 0x0001); // vMinor
      // const {Salt, EncryptedVerifier, EncryptedVerifierHash} = buildHeaderRC4(password);

      const Salt = Buffer.from('0ae902d51faf8b9f02ffca00f30d9c70', 'hex');
      const EncryptedVerifier = '0ad7aea0d0abeb56a5190e6e1ba5e3c0';
      const EncryptedVerifierHash = '24b3058a2fdd4ebe86eb2b754514095f';

      newBlob.write_shift(16, Salt.toString('hex'), 'hex'); // Salt
      // blob.write_shift(16, EncryptedVerifier.toString('hex'), 'hex'); // EncryptedVerifier
      // blob.write_shift(16, EncryptedVerifierHash.toString('hex'), 'hex'); // EncryptedVerifierHash

      newBlob.write_shift(16, EncryptedVerifier, 'hex'); // EncryptedVerifier
      newBlob.write_shift(16, EncryptedVerifierHash, 'hex'); // EncryptedVerifierHash

      data.salt = Salt;
      data.type = 'rc4';
      break;
    case 'rc4_crypto_api':
      const filePassSize = 0x00c8;
      newBlob.write_shift(2, filePassSize); // FilePass size (200 Byte)
      newBlob.write_shift(2, 0x0001); // wEncryptionType
      newBlob.write_shift(2, 0x0004); // vMajor
      newBlob.write_shift(2, 0x0002); // vMinor

      newBlob.write_shift(4, 0x0000000c); // Flags  12
      const HeaderSize = 0x0000007e;
      newBlob.write_shift(4, HeaderSize); // HeaderSize   126

      const {blob: headerBlob, KeySize} = buildHeaderRC4CryptoAPI(HeaderSize);

      newBlob.write_shift(HeaderSize, headerBlob.toString('hex'), 'hex'); // EncryptionHeader

      const encryptionVerifierSize = filePassSize - 14 - HeaderSize; // 200-14-126 = 60 Byte
      const {blob: verifierBlob, Salt: salt1} = buildRC4CryptoAPIEncryptionVerifier(options, encryptionVerifierSize, KeySize);

      newBlob.write_shift(encryptionVerifierSize, verifierBlob.toString('hex'), 'hex'); // EncryptionVerifier

      data.salt = salt1;
      data.type = 'rc4_crypto_api';
      data.keySize = KeySize;
      break;
    default:
      throw new Error('Unsupported encryption algorithms');
  }
  blob.copy(newBlob, filePassRecordLength + blob.l, blob.l, blob.byteLength);

  const output = rc4Encrypt(cfb, newBlob, password, data);
  return output;
}

/**
 * @desc
 */
function buildWorkbookInfo(cfb, blob, options) {
  const {password, type} = options;

  // const dataList1 = iterRecord(blob);

  const bof = blob.read_shift(2);
  const bofSize = blob.read_shift(2);
  blob.l = blob.l + bofSize; // -> skip BOF record

  blob.write_shift(2, 0x002f); // FilePass

  const data = {};
  switch (type) {
    case 'rc4':
      blob.write_shift(2, 0x0036); // FilePass size (54 Byte)
      blob.write_shift(2, 0x0001); // wEncryptionType
      blob.write_shift(2, 0x0001); // vMajor
      blob.write_shift(2, 0x0001); // vMinor
      const {Salt, EncryptedVerifier, EncryptedVerifierHash} = buildHeaderRC4(password);

      blob.write_shift(16, Salt.toString('hex'), 'hex'); // Salt
      // blob.write_shift(16, EncryptedVerifier.toString('hex'), 'hex'); // EncryptedVerifier
      // blob.write_shift(16, EncryptedVerifierHash.toString('hex'), 'hex'); // EncryptedVerifierHash

      blob.write_shift(16, EncryptedVerifier, 'hex'); // EncryptedVerifier
      blob.write_shift(16, EncryptedVerifierHash, 'hex'); // EncryptedVerifierHash

      data.salt = Salt;
      data.type = 'rc4';
      break;
    case 'rc4_crypto_api':
      const filePassSize = 0x00c8;
      blob.write_shift(2, filePassSize); // FilePass size (200 Byte)
      blob.write_shift(2, 0x0001); // wEncryptionType
      blob.write_shift(2, 0x0004); // vMajor
      blob.write_shift(2, 0x0002); // vMinor

      blob.write_shift(4, 0x0000000c); // Flags  12
      const HeaderSize = 0x0000007e;
      blob.write_shift(4, HeaderSize); // HeaderSize   126

      const {blob: headerBlob, KeySize} = buildHeaderRC4CryptoAPI(HeaderSize);

      blob.write_shift(HeaderSize, headerBlob.toString('hex'), 'hex'); // EncryptionHeader

      const encryptionVerifierSize = filePassSize - 14 - HeaderSize; // 200-14-126 = 60 Byte
      const {blob: verifierBlob, Salt: salt1} = buildRC4CryptoAPIEncryptionVerifier(options, encryptionVerifierSize, KeySize);

      blob.write_shift(encryptionVerifierSize, verifierBlob.toString('hex'), 'hex'); // EncryptionVerifier

      data.salt = salt1;
      data.type = 'rc4_crypto_api';
      data.keySize = KeySize;
      break;
    default:
      throw new Error('Unsupported encryption algorithms');
      break;
  }

  const output = rc4Encrypt(cfb, blob, password, data);
  return output;
}


/**
 * @desc
 */
function rc4Encrypt(currCfb, blob, password, data) {
  let buf = [];
  const plainBuf = [];
  blob.l = 0; // Reset Offset

  const dataList = iterRecord(blob);

  // const tempList1 = dataList.map((item)=>{
  //   const temp = {
  //     l: item.l,
  //     num: item.num,
  //     size: item.size,
  //     header: item.header.toString('hex'),
  //     record: item.record.toString('hex'),
  //   };
  //   return temp;
  // });
  // const fs1 = require('fs').promises;
  // fs1.writeFile('record-before.json', JSON.stringify(tempList1));

  for (const {header, num, size, record} of dataList) {
    if (num === recordNameNum.FilePass) {
      plainBuf.push(...header, ...record);
      buf.push(Buffer.alloc(4 + size));
    } else if ([
      recordNameNum.BOF,
      recordNameNum.FilePass,
      recordNameNum.UsrExcl,
      recordNameNum.FileLock,
      recordNameNum.InterfaceHdr,
      recordNameNum.RRDInfo,
      recordNameNum.RRDHead,
    ].includes(num)) {
      plainBuf.push(...header, ...record);
      buf.push(Buffer.alloc(4 + size));
    // The lbPlyPos field of the BoundSheet8 record (section 2.4.28) MUST NOT be encrypted.
    } else if (num === recordNameNum.BoundSheet8) {
      const lbPlyPos = record.slice(0, 4);
      const restSize = size - 4;
      plainBuf.push(...header, ...lbPlyPos, ...Array(restSize).fill(-2));
      buf.push(Buffer.concat([Buffer.alloc(4), Buffer.alloc(4), record.slice(4)]));
    } else {
      if (num === recordNameNum.XF) {
        // @link  https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/b3413c2b-ca5b-4988-86be-ab44bfe9e4d3
        // const ifnt = Buffer.from(record, 'hex').readInt16LE(0); // ifnt-> FontIndex （2Byte）
        const ifnt = record.readInt16LE(0);
        if (ifnt === 23) { // 0x1700 -> 23
          const newRecord = Buffer.concat([Buffer.alloc(2), record.slice(2, size)]);
          plainBuf.push(...header, ...Array(size).fill(-1));
          buf.push(Buffer.concat([Buffer.alloc(4), newRecord]));
        } else {
          plainBuf.push(...header, ...Array(size).fill(-1));
          buf.push(Buffer.concat([Buffer.alloc(4), record]));
        }
      } else {
        if (num === recordNameNum.XFCRC) {
          let newRecord = Buffer.concat([record.slice(0, 16), Buffer.from('a0c70d78', 'hex')]);
          newRecord = record;
          console.log('xxxxxxxx--->', newRecord.toString('hex'));

          plainBuf.push(...header, ...Array(size).fill(-1));
          buf.push(Buffer.concat([Buffer.alloc(4), newRecord]));
        } else {
          plainBuf.push(...header, ...Array(size).fill(-1));
          buf.push(Buffer.concat([Buffer.alloc(4), record]));
        }
      }
      // plainBuf.push(...header, ...Array(size).fill(-1));
      // buf.push(Buffer.concat([Buffer.alloc(4), record]));
    }
  }

  buf = Buffer.concat(buf);

  const {salt, keySize, type} = data;
  let enc;
  const blocksize = 1024;
  if (type === 'rc4') {
    enc = documentRC4.encrypt(password, salt, buf, blocksize);
  } else if (type === 'rc4_crypto_api') {
    enc = documentRC4CryptoAPI.encrypt(password, salt, keySize, buf, blocksize);
  } else {
    // enc = documentXOR.encrypt(password, buf, plainBuf);
  }

  for (let i = 0; i < plainBuf.length; i++) {
    const c = plainBuf[i];
    if (c !== -1 && c !== -2) {
      enc.writeUInt8(c, i);
    }
  }

  let output = CFB.utils.cfb_new();
  CFB.utils.cfb_add(output, 'Workbook', enc);

  const ETExtData = CFB.find(currCfb, 'ETExtData');
  if (ETExtData) {
    CFB.utils.cfb_add(output, 'ETExtData', ETExtData.content);
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

  CFB.utils.prep_blob(enc, 0);
  const dataList1 = iterRecord(enc);
  const tempList = dataList1.map((item)=>{
    const temp = {
      l: item.l,
      num: item.num,
      size: item.size,
      header: item.header.toString('hex'),
      record: item.record.toString('hex'),
    };
    return temp;
  });
  const fs = require('fs').promises;
  fs.writeFile('record.json', JSON.stringify(tempList));

  return output;
}

exports.encrypt = function encrypt(cfb, input, options) {
  // const WorkbookBuffer = buildWorkbookInfo(cfb, input, options);
  // const WorkbookBuffer = buildWorkbookInfo2(cfb, input, options);
  const WorkbookBuffer = buildWorkbookInfo3(cfb, input, options);
  return WorkbookBuffer;
};
