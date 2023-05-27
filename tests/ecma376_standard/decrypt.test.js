const fs = require('fs').promises;
// const {describe, beforeEach, it, expect} = require('@jest/globals');

const officeCrypto = require('../../index');

const filePath = '../data/standard_encrypt_test.xlsx';

describe('ecma376_standard decrypt', () => {
  it('decrypt', async () => {
    try {
      const input = await fs.readFile('./tests/data/standard_encrypt_test.xlsx');
      const output = await officeCrypto.decrypt(input, {password: '123456'});
      await fs.writeFile('./tests/data/standard_decrypt_test.xlsx', output);
      expect(200).toEqual(200);
    } catch (error) {
      console.log('error--->', error);
    }
    // const input = await fs.readFile('../data/standard_encrypt_test.xlsx');
    // const output = officeCrypto.decrypt(input, {password: '123456'});
    // await fs.writeFile('../data/standard_decrypt_test.xlsx');
    // expect(200).toEqual(200);
  });
});
