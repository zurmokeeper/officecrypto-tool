
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const filePath = './tests/data/decrypt';

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
});
