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

  // ------------------------------------------------------------- matrix

  const MASKS: ((x: number, y: number) => boolean)[] = [
    (x, y) => (x + y) % 2 === 0,
    (_x, y) => y % 2 === 0,
    (x) => x % 3 === 0,
    (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
    (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
    (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
    (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
  ];

  class Matrix {
    size: number;
    dark: boolean[][];
    reserved: boolean[][];

    constructor(public version: number) {
      this.size = version * 4 + 17;
      this.dark = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
      this.reserved = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
      this.drawFunctionPatterns();
    }

    set(x: number, y: number, dark: boolean) {
      this.dark[y][x] = dark;
      this.reserved[y][x] = true;
    }

    drawFunctionPatterns() {
      const size = this.size;
      for (let i = 0; i < size; i++) {
        this.set(6, i, i % 2 === 0);
        this.set(i, 6, i % 2 === 0);
      }
      for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
        for (let dy = -4; dy <= 4; dy++) {
          for (let dx = -4; dx <= 4; dx++) {
            const x = cx + dx;
            const y = cy + dy;
            const dist = Math.max(Math.abs(dx), Math.abs(dy));
            if (x >= 0 && x < size && y >= 0 && y < size) this.set(x, y, dist !== 2 && dist !== 4);
          }
        }
      }
      const positions = this.alignmentPositions();
      const last = positions.length - 1;
      positions.forEach((cx, i) =>
        positions.forEach((cy, j) => {
          // No alignment pattern on top of the three finder patterns.
          if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) return;
          for (let dy = -2; dy <= 2; dy++) {
            for (let dx = -2; dx <= 2; dx++) this.set(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
          }
        }),
      );
      this.drawFormatBits(0); // reserves the area, redrawn with the real mask later
      this.drawVersionBits();
    }

    alignmentPositions() {
      if (this.version === 1) return [];
      const numAlign = Math.floor(this.version / 7) + 2;
      const step = Math.ceil((this.version * 4 + 4) / (numAlign * 2 - 2)) * 2;
      const result = [6];
      for (let pos = this.size - 7; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
      return result;
    }

    drawFormatBits(mask: number) {
      const data = (0b00 << 3) | mask; // 00 = error correction level M
      let rem = data;
      for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
      const bits = ((data << 10) | rem) ^ 0x5412;
      const bit = (i: number) => ((bits >>> i) & 1) === 1;
      const size = this.size;
      for (let i = 0; i <= 5; i++) this.set(8, i, bit(i));
      this.set(8, 7, bit(6));
      this.set(8, 8, bit(7));
      this.set(7, 8, bit(8));
      for (let i = 9; i < 15; i++) this.set(14 - i, 8, bit(i));
      for (let i = 0; i < 8; i++) this.set(size - 1 - i, 8, bit(i));
      for (let i = 8; i < 15; i++) this.set(8, size - 15 + i, bit(i));
      this.set(8, size - 8, true);
    }

    drawVersionBits() {
      if (this.version < 7) return;
      let rem = this.version;
      for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
      const bits = (this.version << 12) | rem;
      for (let i = 0; i < 18; i++) {
        const dark = ((bits >>> i) & 1) === 1;
        const a = this.size - 11 + (i % 3);
        const b = Math.floor(i / 3);
        this.set(a, b, dark);
        this.set(b, a, dark);
      }
    }

    /** Places the codewords in the zigzag order, two columns at a time from the right. */
    drawCodewords(codewords: number[]) {
      let i = 0;
      for (let right = this.size - 1; right >= 1; right -= 2) {
        if (right === 6) right = 5;
        for (let vert = 0; vert < this.size; vert++) {
          for (let j = 0; j < 2; j++) {
            const x = right - j;
            const upward = ((right + 1) & 2) === 0;
            const y = upward ? this.size - 1 - vert : vert;
            if (!this.reserved[y][x] && i < codewords.length * 8) {
              this.dark[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) === 1;
              i++;
            }
          }
        }
      }
    }

    applyMask(mask: number) {
      for (let y = 0; y < this.size; y++) {
        for (let x = 0; x < this.size; x++) {
          if (!this.reserved[y][x] && MASKS[mask](x, y)) this.dark[y][x] = !this.dark[y][x];
        }
      }
    }

    /** Simplified penalty score (long runs, 2x2 blocks, dark balance); lower reads better. */
    penalty() {
      const size = this.size;
      let score = 0;
      for (let a = 0; a < size; a++) {
        let rowRun = 1;
        let colRun = 1;
        for (let b = 1; b <= size; b++) {
          if (b < size && this.dark[a][b] === this.dark[a][b - 1]) rowRun++;
          else {
            if (rowRun >= 5) score += rowRun - 2;
            rowRun = 1;
          }
          if (b < size && this.dark[b][a] === this.dark[b - 1][a]) colRun++;
          else {
            if (colRun >= 5) score += colRun - 2;
            colRun = 1;
          }
        }
      }
      let darkCount = 0;
      for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
          if (this.dark[y][x]) darkCount++;
          if (x < size - 1 && y < size - 1) {
            const c = this.dark[y][x];
            if (c === this.dark[y][x + 1] && c === this.dark[y + 1][x] && c === this.dark[y + 1][x + 1]) score += 3;
          }
        }
      }
      score += Math.floor(Math.abs(darkCount * 20 - size * size * 10) / (size * size)) * 10;
      return score;
    }
  }

  /** Returns the QR code for a text as rows of dark (true) and light modules. */
  function encode(text: string) {
    const bytes = new TextEncoder().encode(text);
    const version = chooseVersion(bytes.length);
    const codewords = addErrorCorrection(encodeData(bytes, version), version);
    let best: Matrix | null = null;
    let bestScore = Infinity;
    for (let mask = 0; mask < MASKS.length; mask++) {
      const matrix = new Matrix(version);
      matrix.drawCodewords(codewords);
      matrix.applyMask(mask);
      matrix.drawFormatBits(mask);
      const score = matrix.penalty();
      if (score < bestScore) {
        best = matrix;
        bestScore = score;
      }
    }
    return best!.dark;
  }

  /** An <svg> of the QR code with a quiet zone of 4 modules. */
  function toSvg(text: string) {
    const modules = encode(text);
    const size = modules.length + 8;
    let path = "";
    modules.forEach((row, y) =>
      row.forEach((dark, x) => {
        if (dark) path += `M${x + 4},${y + 4}h1v1h-1z`;
      }),
    );
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    svg.setAttribute("viewBox", `0 0 ${size} ${size}`);
    svg.setAttribute("shape-rendering", "crispEdges");
    svg.setAttribute("class", "qr-code");
    const background = document.createElementNS(ns, "rect");
    background.setAttribute("width", String(size));
    background.setAttribute("height", String(size));
    background.setAttribute("fill", "#ffffff");
    const shape = document.createElementNS(ns, "path");
    shape.setAttribute("d", path);
    shape.setAttribute("fill", "#000000");
    svg.append(background, shape);
    return svg;
  }

  return { encode, toSvg };
})();

(window as any).SeresQR = SeresQR;
