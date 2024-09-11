
const officeCrypto = require('./index');
const fs = require('fs').promises;
let filePath = './tests/data/decrypt';
const CFB = require('cfb');

const xls97 = require('./src/util/xls97');
const common = require('./src/util/common');

(async ()=>{
  // const input = await fs.readFile(`${filePath}/xor_pass_test.xls`);
  // const output = await officeCrypto.decrypt(input, {password: '123456'});
  // await fs.writeFile(`${filePath}/xor_out_success.xls`, output);

  // const input = await fs.readFile(`${filePath}/xor_pass_length_5_test.xls`);
  // const output = await officeCrypto.decrypt(input, {password: 'xxxxx'});
  // await fs.writeFile(`${filePath}/xor_pass_length_5_out_success.xls`, output);

  // const input = await fs.readFile(`./wps-plain - 1 - 副本.xls`);
  // const output = await officeCrypto.decrypt(input, {password: '123456'});
  // await fs.writeFile(`./wps-dec-out.xls`, output);

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
  // const input = await fs.readFile(`./wps-plain.xls`);
  // const output = officeCrypto.encrypt(input, {password: '123456', type: 'rc4'});
  // await fs.writeFile(`./wps-plain-pass-2.xls`, output);
  // return;

  // const input = await fs.readFile(`${filePath}/rc4_cryptoapi_pass_test.xls`);
  // const input = await fs.readFile(`${filePath}/test-case-format.xls`);
  // const input = await fs.readFile(`${filePath}/Book1.1.xls`);
  // const output = await officeCrypto.decrypt(input, {password: '12345678'});

  // const input = await fs.readFile(`${filePath}/rc4_cryptoapi_out_success.xls`);
  // const output = officeCrypto.encrypt(input, {password: '123456', type: 'rc4_crypto_api'});
  // await fs.writeFile(`${filePath}/rc4_cryptoapi_out_test_test.xls`, output);

  // filePath = './tests/data/encrypt';
  // const input = await fs.readFile(`${filePath}/rc4_crypto_api_wait_for_encrypt_test.xls`);
  // const input = await fs.readFile(`${filePath}/rc4_out_success.xls`);
  // const output = officeCrypto.encrypt(input, {password: '123456', type: 'rc4_crypto_api'});
  // await fs.writeFile(`./rc4_crypto_api_pass_out_success.xls`, output);

  // const input = await fs.readFile(`./wps-plain - 1.xls`);
  // const input = await fs.readFile(`./wps-plain-pass.xls`);
  // const cfb = CFB.read(input, {type: 'buffer'});
  // const Workbook = CFB.find(cfb, 'Workbook');
  // const workbookContent = Workbook.content;
  // const bof = workbookContent.read_shift(2);


  // const input = await fs.readFile(`./wps-plain - 1.xls`);
  // const output = await officeCrypto.decrypt(input, {password: '123456'});

  const before = require('./record-before.json');
  // const before = require('./record-before2.json');

  // let index = 0
  // before.map((item, i)=>{
  //   if (item.num === 224 && item.record.substring(0, 2) === '17') {
  //     console.log('xxx', index++);
  //   }
  //   return item;
  // });
  // const buffer1 = before.filter((item)=>item.num === 224).map((item)=>Buffer.from(item.record, 'hex'));

  const buffer1 = before.filter((item)=>item.num === 224).map((item)=>Buffer.from(item.header+item.record, 'hex'));
  const b1 = Buffer.concat(buffer1);
  const number = common.CRC(b1);
  console.log('aa', number);


  // const buffer = Buffer.from('123456789');
  // console.log(buffer.toString('hex')); // 输出转换后的16进制字符串
  // const o = common.CRC(buffer);
  // console.log(o);

  // const number = o; // 你提供的数值

  // // 将数值转换为Buffer对象
  const buf = Buffer.alloc(4); // 创建一个4字节的Buffer
  buf.writeUInt32LE(number, 0); // 将数值写入Buffer，使用大端序
  // buf.writeUInt32BE(number, 0);

  // 将Buffer转换为16进制字符串
  const hexString = buf.toString('hex');

  console.log(hexString); // 输出转换后的16进制字符串
})();
