
const officeCrypto = require('./index');
const fs = require('fs').promises;
const filePath = './tests/test_files/decrypt';

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

  // const input = await fs.readFile(`${filePath}/xor_pass_test_4_book_stream.xls`);
  // const output = await officeCrypto.decrypt(input, {password: 'Password$456'});
  // await fs.writeFile(`./test.xls`, output);

  const input = await fs.readFile(`${filePath}/agile_pass_test.xlsx`);
  // const output = await officeCrypto.decrypt(input, {password: '1234567677'});
  const output = await officeCrypto.decrypt(input, {password: '123456'});
  await fs.writeFile(`./agile_out_success.xlsx`, output);
})();
