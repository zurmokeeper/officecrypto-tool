
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const filePath = './tests/test_files/decrypt';
const encryptFilePath = './tests/test_files/encrypt';

describe('rc4_crypto_api decrypt', () => {
  it('decrypt xls success', async () => {
    const input = await fs.readFile(`${filePath}/rc4_cryptoapi_pass_test.xls`);
    const output = await officeCrypto.decrypt(input, {password: '123'});
    await fs.writeFile(`${filePath}/rc4_cryptoapi_out_success.xls`, output);
    // expect(200).toEqual(200);
  });

  it('decrypt doc success', async () => {
    const input = await fs.readFile(`${filePath}/rc4_cryptoapi_pass_test.doc`);
    const output = await officeCrypto.decrypt(input, {password: '123456'});
    await fs.writeFile(`${filePath}/rc4_cryptoapi_out_success.doc`, output);
    // expect(200).toEqual(200);
  });

  it('decrypt ppt success', async () => {
    const input = await fs.readFile(`${filePath}/rc4_pass.ppt`);
    const output = await officeCrypto.decrypt(input, {password: '123456'});
    await fs.writeFile(`${filePath}/rc4_out_success.ppt`, output);
    // expect(200).toEqual(200);
  });

  it('decrypt unencrypted doc success', async () => {
    const input = await fs.readFile(`${encryptFilePath}/doc_wait_for_encrypt.doc`);
    const output = await officeCrypto.decrypt(input, {password: '123456'});
    await fs.writeFile(`${encryptFilePath}/decrypt_unencrypted_doc_success.doc`, output);
    // expect(200).toEqual(200);
  });

  it('decrypt unencrypted xls success', async () => {
    const input = await fs.readFile(`${encryptFilePath}/xls_wait_for_encrypt.xls`);
    const output = await officeCrypto.decrypt(input, {password: '123456'});
    await fs.writeFile(`${encryptFilePath}/decrypt_unencrypted_doc_success.xls`, output);
    // expect(200).toEqual(200);
  });

  it('decrypt unencrypted xlsx and docx success', async () => {
    const input = await fs.readFile(`${encryptFilePath}/agile_input_test.xlsx`);
    const output = await officeCrypto.decrypt(input, {password: '123456'});
    await fs.writeFile(`${encryptFilePath}/decrypt_unencrypted_xlsx_success.xlsx`, output);
    // expect(200).toEqual(200);
  });

  it('decrypt rc4_crypto_api xls, the password is incorrect', async () => {
    const test = function test() {
      return async function() {
        const input = await fs.readFile(`${filePath}/rc4_cryptoapi_pass_test.xls`);
        const output = await officeCrypto.decrypt(input, {password: 'xxxxx'});
      };
    };
    await expect(test()).rejects.toThrowError(new Error( `The password is incorrect` ));
  });


  it('decrypt rc4_crypto_api ppt, the password is incorrect', async () => {
    const test = function test() {
      return async function() {
        const input = await fs.readFile(`${filePath}/rc4_pass.ppt`);
        const output = await officeCrypto.decrypt(input, {password: 'xxxxx'});
      };
    };
    await expect(test()).rejects.toThrowError(new Error( `The password is incorrect` ));
  });
});
