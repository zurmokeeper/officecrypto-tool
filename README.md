# officecrypto-tool

```
Usage examples：

const officeCrypto = require('officeCrypto');
const fs = require('fs').promises;

//decrypt a file with a password
(async ()=>{
        const input = await fs.readFile(`pass_test.xlsx`);
        const output = await officeCrypto.decrypt(input, {password: '123456'});
        await fs.writeFile(`out_success.xlsx`, output);
})()

//Setting up encrypted files with passwords
(async ()=>{
        const input = await fs.readFile(`test.xlsx`);
        const output = officeCrypto.encrypt(input, {password: '123456'});
        await fs.writeFile(`standard_out_success.xlsx`, output);
})()
```