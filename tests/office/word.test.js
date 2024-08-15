
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const decryptFilePath = './tests/test_files/decrypt';
const encryptFilePath = './tests/test_files/encrypt';

describe('Word isEncrypted', () => {
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
