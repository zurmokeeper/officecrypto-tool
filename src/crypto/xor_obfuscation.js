/* eslint-disable valid-jsdoc */

const padArray = [
  0xBB, 0xFF, 0xFF, 0xBA,
  0xFF, 0xFF, 0xB9, 0x80,
  0x00, 0xBE, 0x0F, 0x00,
  0xBF, 0x0F, 0x00,
];

const initialCode = [
  0xE1F0, 0x1D0F, 0xCC9C, 0x84C0,
  0x110C, 0x0E10, 0xF1CE, 0x313E,
  0x1872, 0xE139, 0xD40F, 0x84F9,
  0x280C, 0xA96A, 0x4EC3,
];

const xorMatrix = [
  0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09, 0x7B61, 0xF6C2, 0xFDA5, 0xEB6B, 0xC6F7, 0x9DCF, 0x2BBF,
  0x4563, 0x8AC6, 0x05AD, 0x0B5A, 0x16B4, 0x2D68, 0x5AD0, 0x0375, 0x06EA, 0x0DD4, 0x1BA8, 0x3750, 0x6EA0, 0xDD40,
  0xD849, 0xA0B3, 0x5147, 0xA28E, 0x553D, 0xAA7A, 0x44D5, 0x6F45, 0xDE8A, 0xAD35, 0x4A4B, 0x9496, 0x390D, 0x721A,
  0xEB23, 0xC667, 0x9CEF, 0x29FF, 0x53FE, 0xA7FC, 0x5FD9, 0x47D3, 0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68, 0xF6D0,
  0xB861, 0x60E3, 0xC1C6, 0x93AD, 0x377B, 0x6EF6, 0xDDEC, 0x45A0, 0x8B40, 0x06A1, 0x0D42, 0x1A84, 0x3508, 0x6A10,
  0xAA51, 0x4483, 0x8906, 0x022D, 0x045A, 0x08B4, 0x1168, 0x76B4, 0xED68, 0xCAF1, 0x85C3, 0x1BA7, 0x374E, 0x6E9C,
  0x3730, 0x6E60, 0xDCC0, 0xA9A1, 0x4363, 0x86C6, 0x1DAD, 0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373, 0x06E6, 0x0DCC,
  0x1021, 0x2042, 0x4084, 0x8108, 0x1231, 0x2462, 0x48C4,
];

/**
 * @desc CreatePasswordVerifier_Method1
 * @link 2.3.7.1 Binary Document Password Verifier Derivation Method 1   https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/fb2d125c-1012-4999-b5ef-15a2bd4bec36
 * @param password
 * @param verificationBytes
 * @returns
 */
exports.verifyPassword = function verifyPassword(password, verificationBytes) {
  let verifier = 0x0000;
  const passwordArray = [];
  passwordArray.push(password.length);
  for (const ch of password) {
    passwordArray.push(ch.charCodeAt(0));
  }
  passwordArray.reverse();
  for (const passwordByte of passwordArray) {
    let intermidiate1; let intermidiate2;
    let intermidiate3;
    if ((verifier & 0x4000) === 0x0000) {
      intermidiate1 = 0;
    } else {
      intermidiate1 = 1;
    }
    intermidiate2 = verifier * 2;
    intermidiate2 = intermidiate2 & 0x7fff;
    intermidiate3 = intermidiate1 ^ intermidiate2;
    verifier = intermidiate3 ^ passwordByte;
  }
  return (verifier ^ 0xCE4B) === verificationBytes;
};


/**
 * @desc CreateXorKey_Method1
 * @param password
 * @returns
 */
function createXorKeyMethod1(password) {
  let xorKey = initialCode[password.length - 1];
  let currentElement = 0x68;
  for (let i = password.length - 1; i >= 0; --i) {
    let char = password[i].charCodeAt(0);
    for (let j = 0; j != 7; ++j) {
      if (char & 0x40) xorKey ^= xorMatrix[currentElement];
      char *= 2;
      --currentElement;
    }
  }
  return xorKey;
}

// rotated right -> ror
const ror = function ror(byte) {
  return ((byte / 2) | (byte * 128)) & 0xFF;
};

const xorRor = function xorRor(byte1, byte2) {
  return ror(byte1 ^ byte2);
};


/**
 * @desc CreateXorArray_Method1
 * @link 2.3.7.2 Binary Document XOR Array Initialization Method 1 https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/72c141a7-5f27-4a60-8164-448bed90546f
 * @param password
 * @returns
 */
function cryptoCreateXorArrayMethod1(password) {
  const xorKey = createXorKeyMethod1(password);

  let index = password.length;

  const obfuscationArray = [0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00];

  let temp; let passwordLastChar; let padIndex;

  if (index % 2 == 1) {
    temp = xorKey >> 8;
    obfuscationArray[index] = xorRor(padArray[0], temp);

    index -= 1;
    temp = (xorKey & 0x00ff);
    passwordLastChar = password[password.length - 1].charCodeAt(0);
    obfuscationArray[index] = xorRor(passwordLastChar, temp);
  }


  while (index > 0) {
    index -= 1;
    temp = xorKey >> 8;
    obfuscationArray[index] = xorRor(password[index].charCodeAt(0), temp);

    index -= 1;
    temp = xorKey & 0x00ff;
    obfuscationArray[index] = xorRor(password[index].charCodeAt(0), temp);
  }

  index = 15;
  padIndex = 15 - password.length;

  while (padIndex > 0) {
    temp = xorKey >> 8;
    obfuscationArray[index] = xorRor(padArray[padIndex], temp);

    index -= 1;
    padIndex -= 1;

    temp = xorKey & 0x00ff;
    obfuscationArray[index] = xorRor(padArray[padIndex], temp);

    index -= 1;
    padIndex -= 1;
  }

  return obfuscationArray;
}


/**
 * @desc DecryptData_Method1
 * @link 2.3.7.3 Binary Document XOR Data Transformation Method 1 https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-offcrypto/75d2b548-18ad-4e26-8aa3-bc5fc37b89af
 * @param password
 * @param input
 * @param plaintext
 * @returns
 */
exports.decrypt = function decrypt(password, input, plaintext) {
  const xorArray = cryptoCreateXorArrayMethod1(password);
  let output = Buffer.alloc(0);

  let dataIndex = 0;

  while (dataIndex < plaintext.length) {
    let count = 1;

    if (plaintext[dataIndex] === -1 || plaintext[dataIndex] === -2) {
      for (let j = dataIndex + 1; j < plaintext.length; j++) {
        if (plaintext[j] >= 0) {
          break;
        }
        count += 1;
      }

      let xorArrayIndex;

      if (plaintext[dataIndex] === -2) {
        xorArrayIndex = (dataIndex + count + 4) % 16;
      } else {
        xorArrayIndex = (dataIndex + count) % 16;
      }

      let tempRes = 0;

      for (let item = 0; item < count; item++) {
        const dataByte = input.slice(0, 1);
        input = input.slice(1);
        tempRes = dataByte[0] ^ xorArray[xorArrayIndex];
        tempRes = ((tempRes >> 5) | (tempRes << 3)) & 0xFF;

        const tempBuf = Buffer.alloc(1);
        tempBuf.writeUIntLE(tempRes, 0, 1);
        output = Buffer.concat([output, tempBuf]);

        xorArrayIndex++;
        xorArrayIndex %= 16;
      }
    } else {
      output = Buffer.concat([output, input.slice(0, 1)]);
      input = input.slice(1);
    }

    dataIndex += count;
  }

  return output;
};
