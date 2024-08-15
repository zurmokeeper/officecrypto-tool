
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const filePath = './tests/test_files/decrypt';

describe('rc4 decrypt', () => {
  it('decrypt xls success', async () => {
    const input = await fs.readFile(`${filePath}/rc4_pass_test.xls`);
    const output = await officeCrypto.decrypt(input, {password: '123456'});
    await fs.writeFile(`${filePath}/rc4_out_success.xls`, output);
    // expect(200).toEqual(200);
  });

  it('decrypt xls and set writeProtect success', async () => {
    const input = await fs.readFile(`${filePath}/rc4_pass_and_writeProtect_test.xls`);
    const output = await officeCrypto.decrypt(input, {password: '123456'});
    await fs.writeFile(`${filePath}/rc4_and_writeProtect_out_success.xls`, output);
    // expect(200).toEqual(200);
  });


  it('decrypt doc success', async () => {
    const input = await fs.readFile(`${filePath}/doc_rc4_pass_test.doc`);
    const output = await officeCrypto.decrypt(input, {password: '123456'});
    await fs.writeFile(`${filePath}/doc_rc4_out_success.doc`, output);
    // expect(200).toEqual(200);
  });

  it('decrypt rc4 xls, the password is incorrect', async () => {
    const test = function test() {
      return async function() {
        const input = await fs.readFile(`${filePath}/rc4_pass_test.xls`);
        const output = await officeCrypto.decrypt(input, {password: 'xxxxx'});
      };
    };
    await expect(test()).rejects.toThrowError(new Error( `The password is incorrect` ));
  });
});
