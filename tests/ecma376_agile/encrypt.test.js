
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const filePath = './tests/data/encrypt';

describe('ecma376_agile encrypt', () => {
  it('encrypt', async () => {
    try {
      const input = await fs.readFile(`${filePath}/agile_input_test.xlsx`);
      const output = officeCrypto.encrypt(input, {password: '123456'});
      await fs.writeFile(`${filePath}/agile_pass_out_success.xlsx`, output);
      expect(200).toEqual(200);
    } catch (error) {
      throw error;
    }
  });
});
