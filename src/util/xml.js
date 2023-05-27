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
 * @desc
 * @param {string} xml
 */
exports.getAgileEncInfo = async function getAgileEncInfo(xml) {
  const parser = new xml2js.Parser({trim: true, explicitArray: false, mergeAttrs: true});
  const result = await parser.parseStringPromise(xml);
  return result.encryption;
};

exports.buildAgileEncInfoXml = function buildAgileEncInfoXml(encryptionInfo) {
  const builder = new xml2js.Builder();
  const xml = builder.buildObject({
    encryption: {
      $: {
        'xmlns': 'http://schemas.microsoft.com/office/2006/encryption',
        'xmlns:p': 'http://schemas.microsoft.com/office/2006/keyEncryptor/password',
        'xmlns:c': 'http://schemas.microsoft.com/office/2006/keyEncryptor/certificate',
      },
      keyData: {
        $: {
          saltSize: encryptionInfo.package.saltValue.length,
          blockSize: encryptionInfo.package.blockSize,
          keyBits: encryptionInfo.package.keyBits,
          hashSize: encryptionInfo.package.hashSize,
          cipherAlgorithm: encryptionInfo.package.cipherAlgorithm,
          cipherChaining: encryptionInfo.package.cipherChaining,
          hashAlgorithm: encryptionInfo.package.hashAlgorithm,
          saltValue: encryptionInfo.package.saltValue.toString('base64'),
        },
      },
      dataIntegrity: {
        $: {
          encryptedHmacKey: encryptionInfo.dataIntegrity.encryptedHmacKey.toString('base64'),
          encryptedHmacValue: encryptionInfo.dataIntegrity.encryptedHmacValue.toString('base64'),
        },
      },
      keyEncryptors: {
        keyEncryptor: {
          '$': {
            uri: 'http://schemas.microsoft.com/office/2006/keyEncryptor/password',
          },
          'p:encryptedKey': {
            $: {
              spinCount: encryptionInfo.key.spinCount,
              saltSize: encryptionInfo.key.saltValue.length,
              blockSize: encryptionInfo.key.blockSize,
              keyBits: encryptionInfo.key.keyBits,
              hashSize: encryptionInfo.key.hashSize,
              cipherAlgorithm: encryptionInfo.key.cipherAlgorithm,
              cipherChaining: encryptionInfo.key.cipherChaining,
              hashAlgorithm: encryptionInfo.key.hashAlgorithm,
              saltValue: encryptionInfo.key.saltValue.toString('base64'),
              encryptedVerifierHashInput: encryptionInfo.key.encryptedVerifierHashInput.toString('base64'),
              encryptedVerifierHashValue: encryptionInfo.key.encryptedVerifierHashValue.toString('base64'),
              encryptedKeyValue: encryptionInfo.key.encryptedKeyValue.toString('base64'),
            },
          },
        },
      },
    },
  });
  return xml;
};

