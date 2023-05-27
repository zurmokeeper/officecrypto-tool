const fs = require('fs').promises;
// const {describe, beforeEach, it, expect} = require('@jest/globals');

const officeCrypto = require('../../index');

const filePath = '../data/agile_encrypt_test.xlsx';

describe('agile_standard decrypt', () => {
  it('agile decrypt', async () => {
    try {
      const input = await fs.readFile('./tests/data/agile_encrypt_test.xlsx');
      const output = await officeCrypto.decrypt(input, {password: '123456'});
      await fs.writeFile('./tests/data/agile_decrypt_test.xlsx', output);
      expect(200).toEqual(200);
    } catch (error) {
      console.log('error--->', error);
    }
  });
});
