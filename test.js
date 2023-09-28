
const officeCrypto = require('./index');
const fs = require('fs').promises;
const filePath = './tests/data/decrypt';

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
  const input = await fs.readFile(`${filePath}/rc4_out_success.ppt`);
  const isEncrypted = officeCrypto.isEncrypted(input);
  console.log('isEncrypted-->', isEncrypted);
})();
