
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const filePath = './tests/data/decrypt';

describe('xor decrypt', () => {
  it('decrypt xls success, password length is 6', async () => {
    const input = await fs.readFile(`${filePath}/xor_pass_test.xls`);
    const output = await officeCrypto.decrypt(input, {password: '123456'});
    await fs.writeFile(`${filePath}/xor_out_success.xls`, output);
    // expect(200).toEqual(200);
  });

  it('decrypt xls success, password length is 5', async () => {
    const input = await fs.readFile(`${filePath}/xor_pass_length_5_test.xls`);
    const output = await officeCrypto.decrypt(input, {password: '12345'});
    await fs.writeFile(`${filePath}/xor_pass_length_5_out_success.xls`, output);
    // expect(200).toEqual(200);
  });

  it('decrypt xor xls, the password is incorrect', async () => {
    const test = function test() {
      return async function() {
        const input = await fs.readFile(`${filePath}/xor_pass_length_5_test.xls`);
        const output = await officeCrypto.decrypt(input, {password: 'xxxxx'});
      };
    };
    await expect(test()).rejects.toThrowError(new Error( `The password is incorrect` ));
  });
});
