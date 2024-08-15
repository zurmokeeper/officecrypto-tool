'use strict';

const ZIP_SIGNATURE = Buffer.from([0x50, 0x4b, 0x03, 0x04]);

exports.isValidZip = function isValidZip(outputFileBuffer) {
  const headerBuffer = outputFileBuffer.slice(0, 4);

  return headerBuffer.equals(ZIP_SIGNATURE);
};
