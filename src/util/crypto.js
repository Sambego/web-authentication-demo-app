export function createRandomUIntArray(size = 32) {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);

  return arr;
}
