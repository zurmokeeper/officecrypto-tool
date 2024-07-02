
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const filePath = './tests/data/encrypt';

describe('xls rc4 encrypt', () => {
  it('encrypt success', async () => {
    const input = await fs.readFile(`${filePath}/rc4_wait_for_encrypt_test.xls`);
    const output = officeCrypto.encrypt(input, {password: '123456', type: 'rc4'});
    await fs.writeFile(`${filePath}/rc4_pass_out_success.xls`, output);
    // expect(200).toEqual(200);
  });

  it('encrypt success, input is ArrayBuffer', async () => {
    const input = await fs.readFile(`${filePath}/rc4_wait_for_encrypt_test.xls`);
    const arrayBuffer = input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength);
    const output = officeCrypto.encrypt(arrayBuffer, {password: '123456', type: 'rc4'});
    await fs.writeFile(`${filePath}/rc4_pass_out_success_arraybuffer.xls`, output);
    // expect(200).toEqual(200);
  });

  it('encrypt success, input is TypeBuffer', async () => {
    const input = await fs.readFile(`${filePath}/rc4_wait_for_encrypt_test.xls`);
    const typeBuffer = new Uint8Array(input);
    const output = officeCrypto.encrypt(typeBuffer, {password: '123456', type: 'rc4'});
    await fs.writeFile(`${filePath}/rc4_pass_out_success_typeBuffer.xls`, output);
    // expect(200).toEqual(200);
  });


  it('encrypt success', async () => {
    const input = await fs.readFile(`${filePath}/rc4_wait_for_encrypt_test.xls`);
    const password = '1234abcd'.repeat(31) + '1234567';
    const output = officeCrypto.encrypt(input, {password, type: 'rc4'});
    await fs.writeFile(`${filePath}/rc4_pass_out_success_255.xls`, output);
    // expect(200).toEqual(200);
  });
});
