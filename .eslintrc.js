module.exports = {
  'extends': ['google'],
  'parserOptions': {
    'ecmaVersion': 2020,
  },
  'env': {
    'es6': true,
  },
  'rules': {
    'linebreak-style': 'off',
    'new-cap': 'off',
    'no-unused-vars': 'warn',
    'camelcase': 'warn',
    'require-jsdoc': 'warn',
    'max-len': ['error', {'code': 300}],
    'no-tabs': 'off',
    'no-mixed-spaces-and-tabs': 'off',
    'one-var': ['warn', 'never'],
    'no-dupe-keys': 2,
  },
};

