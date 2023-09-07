
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const decryptFilePath = './tests/data/decrypt';
const encryptFilePath = './tests/data/encrypt';

describe('Word isEncrypted', () => {
//   it('rc4: The file is encrypted.', async () => {
//     const input = await fs.readFile(`${decryptFilePath}/rc4_pass_test.xls`);
//     const isEncrypted = officeCrypto.isEncrypted(input);
//     expect(isEncrypted).toEqual(true);
//   });

  //   it('rc4 or rc4_crypto_api: The file is not encrypted.', async () => {
  //     const input = await fs.readFile(`${encryptFilePath}/xls_wait_for_encrypt.xls`);
  //     const isEncrypted = officeCrypto.isEncrypted(input);
  //     expect(isEncrypted).toEqual(false);
  //   });

  it('rc4_crypto_api: The file is encrypted.', async () => {
    const input = await fs.readFile(`${decryptFilePath}/rc4_cryptoapi_pass_test.doc`);
    const isEncrypted = officeCrypto.isEncrypted(input);
    expect(isEncrypted).toEqual(true);
  });

  it('The input is not a buffer.', async () => {
    const test = function test() {
      return function() {
        const input = '';
        const isEncrypted = officeCrypto.isEncrypted(input);
      };
    };
    expect(test()).toThrowError(new Error( `The input must be a buffer` ));
  });
});
