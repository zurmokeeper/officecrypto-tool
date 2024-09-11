/* eslint-disable valid-jsdoc */
'use strict';

//     {
//       t: 'standard',
//       h: {
//         Flags: 36,
//         AlgID: 26126,
//         AlgIDHash: 32772,
//         KeySize: 128,
//         ProviderType: 24,
//         CSPName: undefined
//       },
//       v: {
//         Salt: <Buffer 91 33 ca 74 07 dd 5a 2d 04 55 34 91 79 e3 2a e9>,
//         Verifier: <Buffer cf 3f 43 bc 57 d2 56 84 b9 77 01 b0 cc 4c de 6a>,
//         VerifierHash: <Buffer d8 1f 25 99 84 80 20 16 40 88 23 83 0d f9 71 4e 3e 30 71 03 2c f4 86 8b 45 2c
//   10 f7>
//       }
/**
 * @desc
 */
exports.parseEncryptionInfo = function parseEncryptionInfo(blob) {
  const version = parseCryptoVersion(blob);
  switch (version.Minor) {
    case 0x02: return parseEncInfoStandard(blob, version);
    case 0x03: return parseEncInfoExtensible(blob, version);
    case 0x04: return parseEncInfoAgile(blob, version);
  }
  throw new Error('ECMA-376 Encrypted file unrecognized Version: ' + version.Minor);
};

/**
 * @desc
 */
function parseCryptoVersion(blob, length) {
  const o = {};
  o.Major = blob.read_shift(2);
  o.Minor = blob.read_shift(2);
  if (length >= 4) blob.l += length - 4;
  return o;
}

/**
 * @desc
 */
function parseEncInfoStandard(blob) {
  const flags = blob.read_shift(4);
  if ((flags & 0x3F) != 0x24) throw new Error('EncryptionInfo mismatch');
  const sz = blob.read_shift(4);
  // var tgt = blob.l + sz;
  const hdr = parseEncryptionHeader(blob, sz);
  const verifier = parseEncryptionVerifier(blob, blob.length - blob.l);
  return {type: 'standard', h: hdr, v: verifier};
}

/**
 * @desc
 */
function parseEncryptionHeader(blob, length) {
  const tgt = blob.l + length;
  const o = {};
  o.Flags = (blob.read_shift(4) & 0x3F);
  blob.l += 4;
  o.AlgID = blob.read_shift(4);
  let valid = false;
  switch (o.AlgID) {
    case 0x660E: case 0x660F: case 0x6610: valid = (o.Flags == 0x24); break;
    case 0x6801: valid = (o.Flags == 0x04); break;
    case 0: valid = (o.Flags == 0x10 || o.Flags == 0x04 || o.Flags == 0x24); break;
    default: throw new Error('Unrecognized encryption algorithm: ' + o.AlgID);
  }
  if (!valid) throw new Error('Encryption Flags/AlgID mismatch');
  o.AlgIDHash = blob.read_shift(4);
  o.KeySize = blob.read_shift(4);
  o.ProviderType = blob.read_shift(4);
  blob.l += 8;
  o.CSPName = blob.read_shift((tgt - blob.l) >> 1, 'utf16le');
  blob.l = tgt;
  return o;
}

/**
 * @desc
 */
function parseEncryptionVerifier(blob, length) {
  const o = {};
  const tgt = blob.l + length;
  blob.l += 4; // SaltSize must be 0x10
  o.Salt = blob.slice(blob.l, blob.l + 16);
  blob.l += 16;
  o.Verifier = blob.slice(blob.l, blob.l + 16);
  blob.l += 16;
  /* var sz = */blob.read_shift(4);
  o.VerifierHash = blob.slice(blob.l, tgt);
  blob.l = tgt;
  return o;
}

/**
 *
 * @param {*} blob
 * @param {*} length
 * @returns
 */
function parseEncInfoAgile(blob, length) {
  return {type: 'agile'};
}

/**
 *
 * @param {*} blob
 * @param {*} length
 * @returns
 */
function parseEncInfoExtensible(blob, length) {
  return {type: 'extensible'};
}

/**
 * // 初始化 CRC 缓存
 * @returns
 */
function InitCrcCache() {
  const Cache = new Array(256).fill(0);
  for (let Index = 0; Index < 256; ++Index) {
    let Value = Index;
    Value = Value << 24;

    for (let Bit = 0; Bit < 8; ++Bit) {
      if ((Value & 0x80000000) !== 0) {
        Value = (Value << 1) & 0xFFFFFFFF;
        // Value = Value ^ 0x04C11DB7; // CRC-32 polynomial
        // Value = Value ^ 0xEDB88320; // CRC-32 polynomial C#
        Value = Value ^ 0x1EDC6F41; // x32+x7+x5+x3+x2+x+1
      } else {
        Value = (Value << 1) & 0xFFFFFFFF;
      }
    }
    Cache[Index] = Value & 0xFFFF;
  }
  return Cache;
}

/**
 * CRC 计算函数
 * @param {*} CrcValue
 * @param {*} Array
 * @returns
 */
exports.CRC = function CRC(Array) {
  const Cache = InitCrcCache(); // 初始化 CRC 缓存
  let CrcValue = 0xFFFFFFFF;

  for (let i = 0; i < Array.length; ++i) {
    const Byte = Array[i];
    let Index = CrcValue >>> 24; // 取 CrcValue 的高 8 位
    Index = Index ^ Byte; // Index 与 Byte 进行异或操作

    CrcValue = (CrcValue << 8) & 0xFFFFFFFF; // CrcValue 左移 8 位
    CrcValue = CrcValue ^ Cache[Index]; // CrcValue 与 Cache[Index] 进行异或操作
  }

  return CrcValue >>> 0;
};
