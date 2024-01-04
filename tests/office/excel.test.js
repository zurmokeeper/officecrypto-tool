
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');
const { toArrayBuffer } = require('../helpers/common');

const decryptFilePath = './tests/data/decrypt';
const encryptFilePath = './tests/data/encrypt';

describe('Excel isEncrypted', () => {
  it('ecma376_agile: The file is encrypted.', async () => {
    const input = await fs.readFile(`${decryptFilePath}/agile_pass_test.xlsx`);
    const arrayBufferInput = toArrayBuffer(input);
    const isEncrypted = officeCrypto.isEncrypted(input);
    const isArrayBufferInputEncrypted = officeCrypto.isEncrypted(arrayBufferInput);
    expect(isEncrypted).toEqual(true);
    expect(isArrayBufferInputEncrypted).toEqual(true);
  });

  it('ecma376_agile: The file is not encrypted.', async () => {
    const input = await fs.readFile(`${encryptFilePath}/agile_input_test.xlsx`);
    const arrayBufferInput = toArrayBuffer(input);
    const isEncrypted = officeCrypto.isEncrypted(input);
    const isArrayBufferInputEncrypted = officeCrypto.isEncrypted(arrayBufferInput);
    expect(isEncrypted).toEqual(false);
    expect(isArrayBufferInputEncrypted).toEqual(false);
  });


  it('ecma376_standard: The file is encrypted.', async () => {
    const input = await fs.readFile(`${decryptFilePath}/standard_pass_test.xlsx`);
    const arrayBufferInput = toArrayBuffer(input);
    const isEncrypted = officeCrypto.isEncrypted(input);
    const isArrayBufferInputEncrypted = officeCrypto.isEncrypted(arrayBufferInput);
    expect(isEncrypted).toEqual(true);
    expect(isArrayBufferInputEncrypted).toEqual(true);
  });

  it('ecma376_standard: The file is not encrypted.', async () => {
    const input = await fs.readFile(`${encryptFilePath}/standard_wait_for_encrypt.xlsx`);
    const arrayBufferInput = toArrayBuffer(input);
    const isEncrypted = officeCrypto.isEncrypted(input);
    const isArrayBufferInputEncrypted = officeCrypto.isEncrypted(arrayBufferInput);
    expect(isEncrypted).toEqual(false);
    expect(isArrayBufferInputEncrypted).toEqual(false);
  });

  it('rc4: The file is encrypted.', async () => {
    const input = await fs.readFile(`${decryptFilePath}/rc4_pass_test.xls`);
    const arrayBufferInput = toArrayBuffer(input);
    const isEncrypted = officeCrypto.isEncrypted(input);
    const isArrayBufferInputEncrypted = officeCrypto.isEncrypted(arrayBufferInput);
    expect(isEncrypted).toEqual(true);
    expect(isArrayBufferInputEncrypted).toEqual(true);
  });

  it('rc4 or rc4_crypto_api: The file is not encrypted.', async () => {
    const input = await fs.readFile(`${encryptFilePath}/xls_wait_for_encrypt.xls`);
    const arrayBufferInput = toArrayBuffer(input);
    const isEncrypted = officeCrypto.isEncrypted(input);
    const isArrayBufferInputEncrypted = officeCrypto.isEncrypted(arrayBufferInput);
    expect(isEncrypted).toEqual(false);
    expect(isArrayBufferInputEncrypted).toEqual(false);
  });

  it('rc4_crypto_api: The file is encrypted.', async () => {
    const input = await fs.readFile(`${decryptFilePath}/rc4_cryptoapi_pass_test.xls`);
    const arrayBufferInput = toArrayBuffer(input);
    const isEncrypted = officeCrypto.isEncrypted(input);
    const isArrayBufferInputEncrypted = officeCrypto.isEncrypted(arrayBufferInput);
    expect(isEncrypted).toEqual(true);
    expect(isArrayBufferInputEncrypted).toEqual(true);
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
