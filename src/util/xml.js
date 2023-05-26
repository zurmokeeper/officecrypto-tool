'use strict';

const xml2js = require('xml2js');


// `<encryption
//     xmlns="http://schemas.microsoft.com/office/2006/encryption"
//     xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password"
//     xmlns:c="http://schemas.microsoft.com/office/2006/keyEncryptor/certificate">
//     <keyData saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="RL3jtFlXRRCcHsbK+qRC3g=="/>
//     <dataIntegrity encryptedHmacKey="a5BVpFo7DyONZnWWsWo5jHQbm3GB/bz65nooAx90Cc3ZZWOOJvdpqBa4sjUUzBu6L/oRoNEcebpc2gCH4gXpBg==" encryptedHmacValue="4Lpprnxr94jITJbv2eFe8xRV/wNQ1eYDakJUQjGHF2NQTqyUFMK+EfJ4TEzHo34EFhWMSZJ/TMVq+x1g5C01cw=="/>
//     <keyEncryptors>
//         <keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">
//             <p:encryptedKey spinCount="100000" saltSize="16" blockSize="16" keyBits="256" hashSize="64" cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="Sjiwa9DpbAgtT2U7FyJkfA=="
// encryptedVerifierHashInput="ZB62f8MdYZCZwRoeJiChwg==" encryptedVerifierHashValue="sBn8zqKTHGQoCMOfe6Ptlq3n5mLZCx7gRHApQl6CXfvDJolmrsV3/V6/t/spLvRDBR8dcHUySjIHJXIf4ukSmw==" encryptedKeyValue="cqG2QhdLnOd0ENWGT+UMM/lAIlqSxmIKIN7inUuApZU="/>
//         </keyEncryptor>
//     </keyEncryptors>
// </encryption>`
/**
 * @desc @TODO: 补好结构
 * @param {string} xml
 */
exports.getAgileEncInfo = async function getAgileEncInfo(xml) {
  const parser = new xml2js.Parser({trim: true, explicitArray: false, mergeAttrs: true});
  const result = await parser.parseStringPromise(xml);
  console.dir(result);
  console.log(JSON.stringify(result));
  return result.encryption;
};
