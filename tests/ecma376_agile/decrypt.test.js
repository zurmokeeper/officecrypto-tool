
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const filePath = './tests/test_files/decrypt';

describe('ecma376_agile decrypt', () => {
  it('agile decrypt', async () => {
    try {
      const input = await fs.readFile(`${filePath}/agile_pass_test.xlsx`);
      const output = await officeCrypto.decrypt(input, {password: '123456'});
      await fs.writeFile(`${filePath}/agile_out_success.xlsx`, output);
      expect(200).toEqual(200);
    } catch (error) {
      throw error;
    }
  });

  it('agile decrypt, input is ArrayBuffer', async () => {
    try {
      const input = await fs.readFile(`${filePath}/agile_pass_test.xlsx`);
      const arrayBuffer = input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength);
      const output = await officeCrypto.decrypt(arrayBuffer, {password: '123456'});
      await fs.writeFile(`${filePath}/agile_out_success.xlsx`, output);
      expect(200).toEqual(200);
    } catch (error) {
      throw error;
    }
  });

  it('agile decrypt, input is TypeBuffer', async () => {
    try {
      const input = await fs.readFile(`${filePath}/agile_pass_test.xlsx`);
      const typeBuffer = new Uint8Array(input);
      const output = await officeCrypto.decrypt(typeBuffer, {password: '123456'});
      await fs.writeFile(`${filePath}/agile_out_success.xlsx`, output);
      expect(200).toEqual(200);
    } catch (error) {
      throw error;
    }
  });

  it('agile decrypt fails with wrong password, The password is incorrect', async () => {
    try {
      const input = await fs.readFile(`${filePath}/agile_pass_test.xlsx`);
      await officeCrypto.decrypt(input, {password: 'wrong_password'});
    } catch (error) {
      expect(error.message).toBe('The password is incorrect');
    }
  });
});
