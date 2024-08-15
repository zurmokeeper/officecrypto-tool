
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const filePath = './tests/test_files/encrypt';

describe('ecma376_agile encrypt', () => {
  it('encrypt success', async () => {
    const input = await fs.readFile(`${filePath}/agile_input_test.xlsx`);
    const output = officeCrypto.encrypt(input, {password: '123456'});
    await fs.writeFile(`${filePath}/agile_pass_out_success.xlsx`, output);
    // expect(200).toEqual(200);
  });

  it('encrypt success, input is ArrayBuffer', async () => {
    const input = await fs.readFile(`${filePath}/agile_input_test.xlsx`);
    const arrayBuffer = input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength);
    const output = officeCrypto.encrypt(arrayBuffer, {password: '123456'});
    await fs.writeFile(`${filePath}/agile_pass_out_success_arraybuffer.xlsx`, output);
    // expect(200).toEqual(200);
  });

  it('encrypt success, input is TypeBuffer', async () => {
    const input = await fs.readFile(`${filePath}/agile_input_test.xlsx`);
    const typeBuffer = new Uint8Array(input);
    const output = officeCrypto.encrypt(typeBuffer, {password: '123456'});
    await fs.writeFile(`${filePath}/agile_pass_out_success_typeBuffer.xlsx`, output);
    // expect(200).toEqual(200);
  });

  it('encrypt failure. The password length is 256, The maximum password length is 255', async () => {
    const test = function test() {
      return async function() {
        const input = await fs.readFile(`${filePath}/agile_input_test.xlsx`);
        const password = '1234abcd'.repeat(32);
        const output = officeCrypto.encrypt(input, {password});
      };
    };
    expect(test()).rejects.toThrowError(new Error( `The maximum password length is 255` ));
  });


  it('encrypt success', async () => {
    const input = await fs.readFile(`${filePath}/agile_input_test.xlsx`);
    const password = '1234abcd'.repeat(31) + '1234567';
    const output = officeCrypto.encrypt(input, {password});
    await fs.writeFile(`${filePath}/agile_pass_out_success_255.xlsx`, output);
    // expect(200).toEqual(200);
  });

  it('The input is not a buffer.', async () => {
    const test = function test() {
      return function() {
        const input = '';
        const output = officeCrypto.encrypt(input);
      };
    };
    expect(test()).toThrowError(new Error( `The input must be a buffer` ));
  });

  it('Options does not exist.', async () => {
    const test = function test() {
      return async function() {
        const input = await fs.readFile(`${filePath}/agile_input_test.xlsx`);
        const output = officeCrypto.encrypt(input);
      };
    };
    await expect(test()).rejects.toThrowError(new Error( `options.password is required` ));
  });

  it('Options.password does not exist.', async () => {
    const test = function test() {
      return async function() {
        const input = await fs.readFile(`${filePath}/agile_input_test.xlsx`);
        const output = officeCrypto.encrypt(input, {});
      };
    };
    await expect(test()).rejects.toThrowError(new Error( `options.password is required` ));
  });
});
