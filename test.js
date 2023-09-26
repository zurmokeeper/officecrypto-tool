
const officeCrypto = require('./index');
const fs = require('fs').promises;
const filePath = './tests/data/decrypt';

(async ()=>{
  // const input = await fs.readFile(`${filePath}/xor_pass_test.xls`);
  // const output = await officeCrypto.decrypt(input, {password: '123456'});
  // await fs.writeFile(`${filePath}/xor_out_success.xls`, output);

  const input = await fs.readFile(`${filePath}/xor_pass_length_5_test.xls`);
  const output = await officeCrypto.decrypt(input, {password: 'xxxxx'});
  await fs.writeFile(`${filePath}/xor_pass_length_5_out_success.xls`, output);
})();
