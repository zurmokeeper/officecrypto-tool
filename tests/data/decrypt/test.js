
const fs = require('fs').promises;

const officeCrypto = require('../../../index');

const filePath = './tests/data/decrypt';

(async ()=>{
//   const n = 42476;
//   const h = n.toString(16);
//   console.log(h);  // a5ec
  const n = 42476;

  // 创建一个 2 字节的 Buffer
  const buffer = Buffer.alloc(2);

  // 将数字以小端序写入到 Buffer 中
  buffer.writeUInt16LE(n, 0);

  // 将 Buffer 转换为小端序的十六进制字符串
  const hex = buffer.toString('hex');

  console.log(hex); // eca5
  const input = await fs.readFile('doc_rc4_pass_test.doc');
  const output = await officeCrypto.decrypt(input, {password: '123456'});
  await fs.writeFile('doc_rc4_out_success.doc', output);
  // expect(200).toEqual(200)
})();
