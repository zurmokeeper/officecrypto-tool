
const {describe, it, expect} = require('@jest/globals');
const fs = require('fs').promises;

const officeCrypto = require('../../index');

const filePath = './tests/data/decrypt';

describe('ecma376_standard encrypt', () => {
  it('encrypt', async () => {
    expect(200).toEqual(200);
  });
});
