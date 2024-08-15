
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const decryptFilePath = './tests/test_files/decrypt';
const encryptFilePath = './tests/test_files/encrypt';

describe('PPT isEncrypted', () => {
  it('rc4_crypto_api: The file is not encrypted.', async () => {
    const input = await fs.readFile(`${encryptFilePath}/ppt_wait_for_encrypt.ppt`);
    const isEncrypted = officeCrypto.isEncrypted(input);
    expect(isEncrypted).toEqual(false);
  });

  it('rc4_crypto_api: The file is encrypted.', async () => {
    const input = await fs.readFile(`${decryptFilePath}/rc4_pass.ppt`);
    const isEncrypted = officeCrypto.isEncrypted(input);
    expect(isEncrypted).toEqual(true);
  });
});
