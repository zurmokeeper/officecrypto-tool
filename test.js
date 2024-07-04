
const officeCrypto = require('./index');
const fs = require('fs').promises;
let filePath = './tests/data/decrypt';

const xls97 = require('./src/util/xls97');

(async ()=>{
  // const input = await fs.readFile(`${filePath}/xor_pass_test.xls`);
  // const output = await officeCrypto.decrypt(input, {password: '123456'});
  // await fs.writeFile(`${filePath}/xor_out_success.xls`, output);

  // const input = await fs.readFile(`${filePath}/xor_pass_length_5_test.xls`);
  // const output = await officeCrypto.decrypt(input, {password: 'xxxxx'});
  // await fs.writeFile(`${filePath}/xor_pass_length_5_out_success.xls`, output);

  // const input = await fs.readFile(`${filePath}/rc4_pass.ppt`);
  // const output = await officeCrypto.decrypt(input, {password: '123456'});
  // await fs.writeFile(`${filePath}/rc4_out_success.ppt`, output);

  // const input = await fs.readFile(`${filePath}/rc4_pass.ppt`);
  // const input = await fs.readFile(`${filePath}/rc4_out_success.ppt`);
  // const isEncrypted = officeCrypto.isEncrypted(input);
  // console.log('isEncrypted-->', isEncrypted);

  // const input = await fs.readFile(`${filePath}/rc4_pass_and_writeProtect_test.xls`);
  // const output = await officeCrypto.decrypt(input, {password: '123456'});
  // await fs.writeFile(`${filePath}/rc4_and_writeProtect_out_success.xls`, output);

  // const input = await fs.readFile(`${filePath}/rc4_pass_test.xls`);
  // const output = await officeCrypto.decrypt(input, {password: '123456'});


  // const data = xls97.buildHeaderRC4('123456');
  // const input = await fs.readFile(`${filePath}/rc4_out_success.xls`);
  // const output = officeCrypto.encrypt(input, {password: '123456', type: 'rc4'});
  // await fs.writeFile(`${filePath}/rc4_test_test.xls`, output);

  // const input = await fs.readFile(`${filePath}/rc4_cryptoapi_pass_test.xls`);
  // const input = await fs.readFile(`${filePath}/test-case-format.xls`);
  // const input = await fs.readFile(`${filePath}/Book1.1.xls`);
  // const output = await officeCrypto.decrypt(input, {password: '12345678'});

  // const input = await fs.readFile(`${filePath}/rc4_cryptoapi_out_success.xls`);
  // const output = officeCrypto.encrypt(input, {password: '123456', type: 'rc4_crypto_api'});
  // await fs.writeFile(`${filePath}/rc4_cryptoapi_out_test_test.xls`, output);

  // filePath = './tests/data/encrypt';
  // const input = await fs.readFile(`${filePath}/rc4_crypto_api_wait_for_encrypt_test.xls`);
  const input = await fs.readFile(`${filePath}/rc4_out_success.xls`);
  const output = officeCrypto.encrypt(input, {password: '123456', type: 'rc4_crypto_api'});
  await fs.writeFile(`./rc4_crypto_api_pass_out_success.xls`, output);
})();
