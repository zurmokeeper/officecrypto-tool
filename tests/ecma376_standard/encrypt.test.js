
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const filePath = './tests/test_files/encrypt';

describe('ecma376_standard encrypt', () => {
  it('encrypt', async () => {
    const input = await fs.readFile(`${filePath}/standard_wait_for_encrypt.xlsx`);

    const output = officeCrypto.encrypt(input, {password: '123456', type: 'standard'});
    await fs.writeFile(`${filePath}/standard_encrypt_finish.xlsx`, output);
    // expect(200).toEqual(200);
  });

  it(`options.type must be ['standard'], options.type= ''`, async () => {
    const test = function test() {
      return async function() {
        const input = await fs.readFile(`${filePath}/standard_wait_for_encrypt.xlsx`);

        const output = officeCrypto.encrypt(input, {password: '123456', type: ''});
      };
    };
    await expect(test()).rejects.toThrowError(new Error( `options.type must be ['standard']` ));
  });

  it(`options.type must be ['standard'], options.type= 'xx'`, async () => {
    const test = function test() {
      return async function() {
        const input = await fs.readFile(`${filePath}/standard_wait_for_encrypt.xlsx`);

        const output = officeCrypto.encrypt(input, {password: '123456', type: 'xx'});
      };
    };
    await expect(test()).rejects.toThrowError(new Error( `options.type must be ['standard']` ));
  });
});
