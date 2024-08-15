
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const filePath = './tests/test_files/decrypt';

describe('ecma376_standard decrypt', () => {
  it('decrypt success', async () => {
    const input = await fs.readFile(`${filePath}/standard_pass_test.xlsx`);
    const output = await officeCrypto.decrypt(input, {password: '123456'});
    await fs.writeFile(`${filePath}/standard_out_success.xlsx`, output);
    // expect(200).toEqual(200);
  });

  it('The input is not a buffer.', async () => {
    const test = function test() {
      return async function() {
        const input = '';
        const output = await officeCrypto.decrypt(input, {password: '123456'});
        await fs.writeFile(`${filePath}/standard_out_success.xlsx`, output);
      };
    };
    expect(test()).rejects.toThrowError(new Error( `The input must be a buffer` ));
  });

  it('Options does not exist.', async () => {
    const test = function test() {
      return async function() {
        const input = await fs.readFile(`${filePath}/standard_pass_test.xlsx`);
        const output = await officeCrypto.decrypt(input);
        await fs.writeFile(`${filePath}/standard_out_success.xlsx`, output);
      };
    };
    await expect(test()).rejects.toThrowError(new Error( `options.password is required` ));
  });

  it('Options.password does not exist.', async () => {
    const test = function test() {
      return async function() {
        const input = await fs.readFile(`${filePath}/standard_pass_test.xlsx`);
        const output = await officeCrypto.decrypt(input, {});
        await fs.writeFile(`${filePath}/standard_out_success.xlsx`, output);
      };
    };
    await expect(test()).rejects.toThrowError(new Error( `options.password is required` ));
  });

  it('ecma376_standard decrypt fails with wrong password, The password is incorrect', async () => {
    try {
      const input = await fs.readFile(`${filePath}/standard_pass_test.xlsx`);
      await officeCrypto.decrypt(input, {password: 'wrong_password'});
    } catch (error) {
      expect(error.message).toBe('The password is incorrect');
    }
  });
});
