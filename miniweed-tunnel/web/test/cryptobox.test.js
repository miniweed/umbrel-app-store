process.env.APP_SEED = 'a'.repeat(64);

const cryptobox = require('../lib/cryptobox');

function resetSeed(seed) {
  process.env.APP_SEED = seed;
  cryptobox.__resetForTest();
}

test('roundtrip encryption works', () => {
  resetSeed('a'.repeat(64));
  const blob = cryptobox.seal('hunter2');
  expect(cryptobox.open(blob)).toBe('hunter2');
});

test('tampering detection throws', () => {
  resetSeed('a'.repeat(64));
  const blob = cryptobox.seal('hunter2');
  blob.c = Buffer.from('ZZZZ').toString('base64');
  expect(() => cryptobox.open(blob)).toThrow();
});

test('different seeds cannot decrypt old payload', () => {
  resetSeed('a'.repeat(64));
  const blob = cryptobox.seal('secret');
  resetSeed('b'.repeat(64));
  expect(() => cryptobox.open(blob)).toThrow();
});
