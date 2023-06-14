
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const filePath = './tests/data/decrypt';

describe('rc4_crypto_api decrypt', () => {
  it('decrypt success', async () => {
    const input = await fs.readFile(`${filePath}/rc4_cryptoapi_pass_test.xls`);
    const output = await officeCrypto.decrypt(input, {password: '123'});
    await fs.writeFile(`${filePath}/rc4_cryptoapi_out_success.xls`, output);
    // expect(200).toEqual(200);
  });
});
