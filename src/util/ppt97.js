/* eslint-disable valid-jsdoc */

const CFB = require('cfb');
const documentRC4CryptoAPI = require('../crypto/rc4_cryptoapi');

const getBitSlice = (bits, i, w) => (bits & ((2 ** w - 1) << i)) >> i;

const setBitSlice = (bits, i, w, v) => (bits & ~((2 ** w - 1) << i)) | ((v & (2 ** w - 1)) << i);


const parseRecordHeader = function parseRecordHeader(blob) {
  CFB.utils.prep_blob(blob, 0);

  const buf = blob.read_shift(2);
  const recVer = getBitSlice(buf, 0, 4);
  const recInstance = getBitSlice(buf, 4, 12);
  const recType = blob.read_shift(2);
  const recLen = blob.read_shift(4);

  return {
    recVer,
    recInstance,
    recType,
    recLen,
  };
};


const parseCurrentUserAtom = function parseCurrentUserAtom(blob) {
  const start = blob.l;
  const buf = blob.slice(blob.l, blob.l + 8);
  const recordHeader = parseRecordHeader(buf);

  //   assert recordHeader.recVer == 0x0
  //   assert recordHeader.recInstance == 0x000
  //   assert recordHeader.recType == 0x0FF6  // 4086

  blob.l = blob.l + 8;
  const size = blob.read_shift(4); // UInt32LE

  //   assert size == 0x00000014

  const headerToken = blob.readUInt32LE(blob.l); // UInt32LE
  blob.l = blob.l + 4;

  const offsetToCurrentEdit = blob.read_shift(4); // UInt32LE
  const lenUserName = blob.read_shift(2);
  const docFileVersion = blob.read_shift(2);
  const majorVersion = blob.read_shift(1);
  const minorVersion = blob.read_shift(1);
  const unused = blob.slice(blob.l, blob.l + 2);
  blob.l = blob.l + 2;

  const ansiUserName = blob.slice(blob.l, blob.l + lenUserName);
  blob.l = blob.l + lenUserName;

  const relVersion = blob.read_shift(4); // UInt32LE
  const unicodeUserName = blob.slice(blob.l, blob.l + 2 * lenUserName);
  blob.l = blob.l + 2 * lenUserName;

  return {
    rh: recordHeader,
    size,
    headerToken,
    offsetToCurrentEdit,
    lenUserName,
    docFileVersion,
    majorVersion,
    minorVersion,
    unused,
    ansiUserName,
    relVersion,
    unicodeUserName,
    buffer: blob.slice(start, blob.l),
  };
};


const parseCurrentUser = exports.parseCurrentUser = function parseCurrentUser(blob) {
  return {currentUserAtom: parseCurrentUserAtom(blob)};
};

const parseUserEditAtom = exports.parseUserEditAtom = function parseUserEditAtom(blob) {
  const start = blob.l;
  let buf = blob.slice(blob.l, blob.l + 8);
  const recordHeader = parseRecordHeader(buf); // recLen = 32

  //   assert recordHeader.recVer == 0x0
  //   assert recordHeader.recInstance == 0x000
  //   assert recordHeader.recType == 0x0FF5  // 4085
  //   assert recordHeader.recLen == 0x0000001C or recordHeader.recLen == 0x00000020  # 0x0000001c + len(encryptSessionPersistIdRef)

  blob.l = blob.l + 8;
  const lastSlideIdRef = blob.read_shift(4); // UInt32LE
  const version = blob.read_shift(2);
  const minorVersion = blob.read_shift(1);
  const majorVersion = blob.read_shift(1);
  const offsetLastEdit = blob.read_shift(4); // UInt32LE
  const offsetPersistDirectory = blob.read_shift(4); // UInt32LE
  const docPersistIdRef = blob.read_shift(4); // UInt32LE
  const persistIdSeed = blob.read_shift(4); // UInt32LE
  const lastView = blob.read_shift(2);

  const unused = blob.slice(blob.l, blob.l + 2);
  blob.l = blob.l + 2;

  buf = blob.slice(blob.l, blob.l + 4);
  let encryptSessionPersistIdRef = null;
  if (buf.byteLength === 4) {
    encryptSessionPersistIdRef = blob.read_shift(4); // UInt32LE
  }

  return {
    rh: recordHeader,
    lastSlideIdRef,
    version,
    majorVersion,
    minorVersion,
    offsetLastEdit,
    offsetPersistDirectory,
    docPersistIdRef,
    persistIdSeed,
    lastView,
    unused,
    encryptSessionPersistIdRef,
    buffer: blob.slice(start, blob.l),
  };
};

const parsePersistDirectoryEntry = function parsePersistDirectoryEntry(blob) {
  const buf = blob.read_shift(4);
  const persistId = getBitSlice(buf, 0, 20);
  const cPersist = getBitSlice(buf, 20, 12);

  const sizeRgPersistOffset = 4 * cPersist;

  const rgPersistOffsetBlob = blob.slice(blob.l, blob.l + sizeRgPersistOffset);
  blob.l = blob.l + sizeRgPersistOffset;

  CFB.utils.prep_blob(rgPersistOffsetBlob, 0);

  const rgPersistOffset = [];
  let pos = 0;
  while (pos < sizeRgPersistOffset) {
    const persistOffsetEntry = rgPersistOffsetBlob.read_shift(4);
    rgPersistOffset.push(persistOffsetEntry);
    pos += 4;
  }
  return {
    persistId,
    cPersist,
    rgPersistOffset,
  };
};


const parsePersistDirectoryAtom = function parsePersistDirectoryAtom(blob) {
  const start = blob.l;
  const buf = blob.slice(blob.l, blob.l + 8);
  const recordHeader = parseRecordHeader(buf); // recLen = 32

  //   assert recordHeader.recVer == 0x0
  //   assert recordHeader.recInstance == 0x000
  //   assert recordHeader.recType == 0x1772  //

  blob.l = blob.l + 8;

  const rgPersistDirEntryBlob = blob.slice(blob.l, blob.l + recordHeader.recLen);
  blob.l = blob.l + recordHeader.recLen;
  CFB.utils.prep_blob(rgPersistDirEntryBlob, 0);

  const rgPersistDirEntry = [];
  let pos = 0;

  while (pos < recordHeader.recLen) {
    const persistDirectoryEntry = parsePersistDirectoryEntry(rgPersistDirEntryBlob);
    const sizePersistDirectoryEntry = 4 + 4 * persistDirectoryEntry.rgPersistOffset.length;
    rgPersistDirEntry.push(persistDirectoryEntry);
    pos += sizePersistDirectoryEntry;
  }

  return {
    rh: recordHeader,
    rgPersistDirEntry,
    buffer: blob.slice(start, blob.l),
  };
};


const constructPersistObjectDirectory = function constructPersistObjectDirectory(currentUserBlob, powerPointBlob) {
  const currentUser = parseCurrentUser(currentUserBlob);
  const {currentUserAtom} = currentUser;

  powerPointBlob.l = currentUserAtom.offsetToCurrentEdit; // 46125

  const persistDirectoryAtomStack = [];

  for (let index = 0; index < 1; index++) {
    const userEditAtom = parseUserEditAtom(powerPointBlob);
    powerPointBlob.l = userEditAtom.offsetPersistDirectory; // 46097

    const persistDirectoryAtom = parsePersistDirectoryAtom(powerPointBlob);

    persistDirectoryAtomStack.push(persistDirectoryAtom);

    if (userEditAtom.offsetLastEdit === 0) {
      break;
    } else {
      powerPointBlob.l = userEditAtom.offsetLastEdit; // 0
    }
  }

  const persistObjectDirectory = {};

  while (persistDirectoryAtomStack.length > 0) {
    const {rgPersistDirEntry} = persistDirectoryAtomStack.pop();
    for (const {rgPersistOffset, persistId} of rgPersistDirEntry) {
      // eslint-disable-next-line guard-for-in
      for (const i in rgPersistOffset) {
        persistObjectDirectory[persistId + Number(i)] = rgPersistOffset[i];
      }
    }
  }

  return persistObjectDirectory;
};

const parseCryptSession10Container = function parseCryptSession10Container(blob) {
  const buf = blob.slice(blob.l, blob.l + 8);
  const recordHeader = parseRecordHeader(buf); // recLen = 32

  // assert rh.recVer == 0xF
  // # assert rh.recInstance == 0x000
  // assert rh.recType == 0x2F14

  blob.l = blob.l + 8;

  const data = blob.slice(blob.l, blob.l + recordHeader.recLen);
  return {
    rh: recordHeader,
    data,
  };
};

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

const packCurrentUser = function packCurrentUser(currentUser) {
  const {buffer, headerToken} = currentUser.currentUserAtom;
  // rh -> 8 bytes size -> 4 bytes   12 = rh + size
  const buf1 = buffer.slice(0, 12);

  // 16 = rh + size + headerToken(4) Skip the old headerToken
  const buf3 = buffer.slice(16);

  const blob = Buffer.alloc(4);
  CFB.utils.prep_blob(blob, 0);
  blob.write_shift(4, headerToken);

  const newCurrentUserBuffer = Buffer.concat([buf1, blob, buf3]);
  return newCurrentUserBuffer;
};

const packUserEditAtom = function packUserEditAtom(userEditAtom) {
  const {buffer, rh, encryptSessionPersistIdRef} = userEditAtom;
  // recVer + recInstance + recType -> 4 bytes
  const buf1 = buffer.slice(0, 4);

  const recLenBlob = Buffer.alloc(4);
  CFB.utils.prep_blob(recLenBlob, 0);
  recLenBlob.write_shift(4, rh.recLen);

  // 8 = rh  Skip the old recLen   The offset before encryptSessionPersistIdRef is 28 + 8
  const buf3 = buffer.slice(8, 36);

  const encryptSessionPersistIdRefBlob = Buffer.alloc(4);
  CFB.utils.prep_blob(encryptSessionPersistIdRefBlob, 0);
  encryptSessionPersistIdRefBlob.write_shift(4, encryptSessionPersistIdRef);

  const buf5 = buffer.slice(40);

  const newUserEditAtomBuffer = Buffer.concat([buf1, recLenBlob, buf3, encryptSessionPersistIdRefBlob, buf5]);
  return newUserEditAtomBuffer;
};

const packPersistDirectoryEntry = function packPersistDirectoryEntry(entry, size) {
  const {persistId, cPersist, rgPersistOffset} = entry;
  const blob = Buffer.alloc(size);
  CFB.utils.prep_blob(blob, 0);

  let buf = 0xFFFFFFFF;
  buf = setBitSlice(buf, 0, 20, persistId);
  buf = setBitSlice(buf, 20, 12, cPersist);
  blob.write_shift(4, buf);

  for (let index = 0; index < rgPersistOffset.length; index++) {
    const element = rgPersistOffset[index];
    blob.write_shift(4, element);
  }
  return blob;
};

const packPersistDirectoryAtom = function packPersistDirectoryAtom(persistDirectoryAtom) {
  const {buffer, rgPersistDirEntry, rh} = persistDirectoryAtom;
  const buf1 = buffer.slice(0, 8); // rh

  const size = rh.recLen;
  const entryBufferList = rgPersistDirEntry.map((entry)=>{
    return packPersistDirectoryEntry(entry, size);
  });
  const newPersistDirectoryAtomBuffer = Buffer.concat([buf1, ...entryBufferList]);
  return newPersistDirectoryAtomBuffer;
};


exports.decrypt = function decrypt(currCfb, powerPointBlob, password, input) {
  if (!Buffer.isBuffer(powerPointBlob)) powerPointBlob = Buffer.from(powerPointBlob);

  const CurrentUser = CFB.find(currCfb, 'Current User');
  if (!CurrentUser) {
    throw new Error('Current User does not exist');
  }
  let currentUserBlob = CurrentUser.content;
  if (!Buffer.isBuffer(currentUserBlob)) {
    currentUserBlob = Buffer.from(currentUserBlob);
    CFB.utils.prep_blob(currentUserBlob, 0);
  }
  const persistObjectDirectory = constructPersistObjectDirectory(currentUserBlob, powerPointBlob);

  currentUserBlob.l = 0;
  const currentUser = parseCurrentUser(currentUserBlob);

  powerPointBlob.l = currentUser.currentUserAtom.offsetToCurrentEdit;
  const userEditAtom = parseUserEditAtom(powerPointBlob);


  const cryptSession10ContainerOffset = persistObjectDirectory[userEditAtom.encryptSessionPersistIdRef];

  powerPointBlob.l = cryptSession10ContainerOffset;

  // You have to have this or the offset will be off.
  const cryptSession10Container = parseCryptSession10Container(powerPointBlob);

  const vMajor = powerPointBlob.read_shift(2);
  const vMinor = powerPointBlob.read_shift(2);

  if (![0x0002, 0x0003, 0x0004].includes(vMajor) && vMinor !== 0x0002) {
    throw new Error('Unsupported encryption algorithms');
  }
  const data = {};
  const Flags = powerPointBlob.read_shift(4);
  const HeaderSize = powerPointBlob.read_shift(4);
  const info = parseHeaderRC4CryptoAPI(powerPointBlob, HeaderSize);
  const {KeySize} = info;
  const {Salt, EncryptedVerifier, EncryptedVerifierHash} = parseRC4CryptoAPIEncryptionVerifier(powerPointBlob);
  data.salt = Salt;
  data.type = 'rc4_crypto_api';
  data.keySize = KeySize;
  const invalid = documentRC4CryptoAPI.verifyPassword(password, Salt, KeySize, EncryptedVerifier, EncryptedVerifierHash );
  if (!invalid) throw new Error('The password is incorrect');

  // 0xE391C05F: The file SHOULD NOT<6> be an encrypted document.
  currentUser.currentUserAtom.headerToken = 0xE391C05F;


  const newCurrentUserBuffer = packCurrentUser(currentUser);
  const powerPointDecBuf = Buffer.alloc(powerPointBlob.byteLength);

  userEditAtom.encryptSessionPersistIdRef = 0; // Clear
  userEditAtom.rh.recLen = userEditAtom.rh.recLen - 4; // Omit encryptSessionPersistIdRef field

  const newUserEditAtomBuffer = packUserEditAtom(userEditAtom);

  const offsetToCurrentEdit = currentUser.currentUserAtom.offsetToCurrentEdit;
  newUserEditAtomBuffer.copy(powerPointDecBuf, offsetToCurrentEdit, 0, newUserEditAtomBuffer.byteLength);

  powerPointBlob.l = userEditAtom.offsetPersistDirectory;
  const persistDirectoryAtom = parsePersistDirectoryAtom(powerPointBlob);

  persistDirectoryAtom.rgPersistDirEntry[0].cPersist = persistDirectoryAtom.rgPersistDirEntry[0].cPersist - 1;


  const newPersistDirectoryAtomBuffer = packPersistDirectoryAtom(persistDirectoryAtom);
  const offsetPersistDirectory = userEditAtom.offsetPersistDirectory;
  newPersistDirectoryAtomBuffer.copy(powerPointDecBuf, offsetPersistDirectory, 0, newPersistDirectoryAtomBuffer.byteLength);

  let i = 1;
  // eslint-disable-next-line guard-for-in
  for (const key in persistObjectDirectory) {
    const offset = persistObjectDirectory[key];
    powerPointBlob.l = offset;
    const buf = powerPointBlob.slice(powerPointBlob.l, powerPointBlob.l + 8);
    const rh = parseRecordHeader(buf);

    if (rh.recType === 0x2F14) {
      const buffer = Buffer.alloc(8 + rh.recLen, 0x00);
      buffer.copy(powerPointDecBuf, offset, 0, buffer.byteLength);
      continue;
    }

    if ([0x0FF5, 0x1772].includes(rh.recType)) {
      continue;
    }
    i++;
    const recLen = persistObjectDirectory[i] - offset - 8;
    const encryptedBuf = powerPointBlob.slice(offset, offset + 8 + recLen);
    const blocksize = data.keySize * (Math.floor((8 + recLen) / data.keySize) + 1);
    const dec = documentRC4CryptoAPI.decrypt(password, data.salt, data.keySize, encryptedBuf, blocksize, Number(key));
    dec.copy(powerPointDecBuf, offset, 0, dec.byteLength);
  }

  let output = CFB.utils.cfb_new();
  CFB.utils.cfb_add(output, 'Current User', newCurrentUserBuffer);
  CFB.utils.cfb_add(output, 'PowerPoint Document', powerPointDecBuf);

  const Pictures = CFB.find(currCfb, 'Pictures');
  if (Pictures) {
    CFB.utils.cfb_add(output, 'Pictures', Pictures.content);
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
};
