// Small QR code generator for invite links (byte mode, error correction level M,
// versions 1-10, i.e. up to 213 bytes). It is part of SereS itself because the
// Content-Security-Policy only allows our own scripts. Follows ISO/IEC 18004.

const SeresQR = (() => {
  // Level M: error correction codewords per block and number of blocks, by version.
  const ECC_PER_BLOCK = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26];
  const NUM_BLOCKS = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5];
  const MAX_VERSION = 10;

  // ------------------------------------------------------ Reed-Solomon

  /** Multiplication in GF(2^8) with the QR polynomial x^8 + x^4 + x^3 + x^2 + 1. */
  function gfMultiply(x: number, y: number) {
    let z = 0;
    for (let i = 7; i >= 0; i--) {
      z = (z << 1) ^ ((z >>> 7) * 0x11d);
      z ^= ((y >>> i) & 1) * x;
    }
    return z;
  }

  function rsDivisor(degree: number) {
    const result: number[] = new Array(degree).fill(0);
    result[degree - 1] = 1;
    let root = 1;
    for (let i = 0; i < degree; i++) {
      for (let j = 0; j < degree; j++) {
        result[j] = gfMultiply(result[j], root);
        if (j + 1 < degree) result[j] ^= result[j + 1];
      }
      root = gfMultiply(root, 0x02);
    }
    return result;
  }

  function rsRemainder(data: number[], divisor: number[]) {
    const result: number[] = divisor.map(() => 0);
    for (const value of data) {
      const factor = value ^ (result.shift() as number);
      result.push(0);
      divisor.forEach((coef, i) => (result[i] ^= gfMultiply(coef, factor)));
    }
    return result;
  }

  // ------------------------------------------------------ data codewords

  /** Number of modules that can hold data (everything except function patterns). */
  function rawModules(version: number) {
    let result = (16 * version + 128) * version + 64;
    if (version >= 2) {
      const numAlign = Math.floor(version / 7) + 2;
      result -= (25 * numAlign - 10) * numAlign - 55;
      if (version >= 7) result -= 36;
    }
    return result;
  }

  function dataCodewords(version: number) {
    return Math.floor(rawModules(version) / 8) - ECC_PER_BLOCK[version] * NUM_BLOCKS[version];
  }

  function chooseVersion(byteLength: number) {
    for (let version = 1; version <= MAX_VERSION; version++) {
      const bits = 4 + (version < 10 ? 8 : 16) + 8 * byteLength;
      if (bits <= dataCodewords(version) * 8) return version;
    }
    throw new Error("Text is too long for a QR code");
  }

  /** Mode indicator, length, the bytes themselves, terminator and padding. */
  function encodeData(bytes: Uint8Array, version: number) {
    const bits: number[] = [];
    const push = (value: number, length: number) => {
      for (let i = length - 1; i >= 0; i--) bits.push((value >>> i) & 1);
    };
    push(0b0100, 4);
    push(bytes.length, version < 10 ? 8 : 16);
    bytes.forEach((b) => push(b, 8));
    const capacity = dataCodewords(version) * 8;
    push(0, Math.min(4, capacity - bits.length));
    push(0, (8 - (bits.length % 8)) % 8);
    for (let pad = 0xec; bits.length < capacity; pad ^= 0xec ^ 0x11) push(pad, 8);

    const words: number[] = [];
    for (let i = 0; i < bits.length; i += 8) {
      words.push(bits.slice(i, i + 8).reduce((acc, bit) => (acc << 1) | bit, 0));
    }
    return words;
  }

  /** Splits the data into blocks, appends error correction and interleaves them. */
  function addErrorCorrection(data: number[], version: number) {
    const numBlocks = NUM_BLOCKS[version];
    const eccLength = ECC_PER_BLOCK[version];
    const rawCodewords = Math.floor(rawModules(version) / 8);
    const numShortBlocks = numBlocks - (rawCodewords % numBlocks);
    const shortBlockLength = Math.floor(rawCodewords / numBlocks);
    const divisor = rsDivisor(eccLength);

    const blocks: number[][] = [];
    for (let i = 0, k = 0; i < numBlocks; i++) {
      const block = data.slice(k, k + shortBlockLength - eccLength + (i < numShortBlocks ? 0 : 1));
      k += block.length;
      const ecc = rsRemainder(block, divisor);
      if (i < numShortBlocks) block.push(0);
      blocks.push(block.concat(ecc));
    }

    const result: number[] = [];
    for (let i = 0; i < blocks[0].length; i++) {
      blocks.forEach((block, j) => {
        // Skip the padding byte of the short blocks.
        if (i !== shortBlockLength - eccLength || j >= numShortBlocks) result.push(block[i]);
      });
    }
    return result;
  }

  return { chooseVersion, encodeData, addErrorCorrection, rsRemainder, rsDivisor };
})();

(window as any).SeresQR = SeresQR;
