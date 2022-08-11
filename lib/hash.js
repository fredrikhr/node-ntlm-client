/* eslint-disable no-plusplus */
/* eslint-disable no-bitwise */
const crypto = require('crypto');

/**
 * @param {Buffer} key
 * @param {crypto.BinaryLike} message
 */
function calculateDES(key, message) {
  const [key0 = 0, key1 = 0, key2 = 0, key3 = 0, key4 = 0, key5 = 0, key6 = 0] =
    key;
  const desKey = Buffer.alloc(8);

  desKey[0] = key0 & 0xfe;
  desKey[1] = ((key0 << 7) & 0xff) | (key1 >> 1);
  desKey[2] = ((key1 << 6) & 0xff) | (key2 >> 2);
  desKey[3] = ((key2 << 5) & 0xff) | (key3 >> 3);
  desKey[4] = ((key3 << 4) & 0xff) | (key4 >> 4);
  desKey[5] = ((key4 << 3) & 0xff) | (key5 >> 5);
  desKey[6] = ((key5 << 2) & 0xff) | (key6 >> 6);
  desKey[7] = (key6 << 1) & 0xff;

  for (let i = 0; i < 8; i++) {
    let parity = 0;

    for (let j = 1; j < 8; j++) {
      // @ts-ignore
      parity += (desKey[i] >> j) % 2;
    }

    desKey[i] |= parity % 2 === 0 ? 1 : 0;
  }

  const des = crypto.createCipheriv('DES-ECB', desKey, '');
  return des.update(message);
}

/**
 * @param {Parameters<typeof crypto.createHmac>[1]} ntlmhash
 * @param {string} username
 * @param {string} authTargetName
 */
function createNTLMv2Hash(ntlmhash, username, authTargetName) {
  const hmac = crypto.createHmac('md5', ntlmhash);
  hmac.update(Buffer.from(username.toUpperCase() + authTargetName, 'ucs2'));
  return hmac.digest();
}

module.exports = {
  /** @param {string} password */
  createLMHash(password) {
    const buf = Buffer.alloc(16);
    const pwBuffer = Buffer.alloc(14);
    const magicKey = Buffer.from('KGS!@#$%', 'ascii');

    if (password.length > 14) {
      buf.fill(0);
      return buf;
    }

    pwBuffer.fill(0);
    pwBuffer.write(password.toUpperCase(), 0, 'ascii');

    return Buffer.concat([
      calculateDES(pwBuffer.subarray(0, 7), magicKey),
      calculateDES(pwBuffer.subarray(7), magicKey),
    ]);
  },

  /** @param {string} password */
  createNTLMHash(password) {
    const md4sum = crypto.createHash('md4');
    md4sum.update(Buffer.from(password, 'ucs2'));
    return md4sum.digest();
  },

  /**
   * @param {crypto.BinaryLike} challenge
   * @param {Buffer} lmhash
   */
  createLMResponse(challenge, lmhash) {
    const buf = Buffer.alloc(24);
    const pwBuffer = Buffer.alloc(21);

    lmhash.copy(pwBuffer);

    calculateDES(pwBuffer.subarray(0, 7), challenge).copy(buf);
    calculateDES(pwBuffer.subarray(7, 14), challenge).copy(buf, 8);
    calculateDES(pwBuffer.subarray(14), challenge).copy(buf, 16);

    return buf;
  },

  /**
   * @param {crypto.BinaryLike} challenge
   * @param {Buffer} ntlmhash
   */
  createNTLMResponse(challenge, ntlmhash) {
    const buf = Buffer.alloc(24);
    const ntlmBuffer = Buffer.alloc(21);

    ntlmhash.copy(ntlmBuffer);

    calculateDES(ntlmBuffer.subarray(0, 7), challenge).copy(buf);
    calculateDES(ntlmBuffer.subarray(7, 14), challenge).copy(buf, 8);
    calculateDES(ntlmBuffer.subarray(14), challenge).copy(buf, 16);

    return buf;
  },

  /**
   * @param {ReturnType<typeof import('./ntlm').decodeType2Message>} type2message
   * @param {string} username
   * @param {crypto.BinaryLike | crypto.KeyObject} ntlmhash
   * @param {string | null | undefined} nonce
   * @param {string} targetName
   */
  createLMv2Response(type2message, username, ntlmhash, nonce, targetName) {
    const { createPseudoRandomValue } = module.exports;

    const buf = Buffer.alloc(24);
    const ntlm2hash = createNTLMv2Hash(ntlmhash, username, targetName);
    const hmac = crypto.createHmac('md5', ntlm2hash);

    // server challenge
    type2message.challenge.copy(buf, 8);

    // client nonce
    buf.write(nonce || createPseudoRandomValue(16), 16, 'hex');

    // create hash
    hmac.update(buf.subarray(8));
    const hashedBuffer = hmac.digest();

    hashedBuffer.copy(buf);

    return buf;
  },

  /**
   * @param {ReturnType<typeof import('./ntlm').decodeType2Message>} type2message
   * @param {string} username
   * @param {crypto.BinaryLike | crypto.KeyObject} ntlmhash
   * @param {string | null | undefined} nonce
   * @param {string} targetName
   */
  createNTLMv2Response(type2message, username, ntlmhash, nonce, targetName) {
    const { createPseudoRandomValue } = module.exports;

    const {
      buffer: targetInfoBuf = {
        length: 0,
        copy() {},
      },
    } = type2message.targetInfo;
    const buf = Buffer.alloc(48 + targetInfoBuf.length);
    const ntlm2hash = createNTLMv2Hash(ntlmhash, username, targetName);
    const hmac = crypto.createHmac('md5', ntlm2hash);

    // the first 8 bytes are spare to store the hashed value before the blob

    // server challenge
    type2message.challenge.copy(buf, 8);

    // blob signature
    buf.writeUInt32BE(0x01010000, 16);

    // reserved
    buf.writeUInt32LE(0, 20);

    // timestamp
    // TODO: we are loosing precision here since js is not able to handle those large integers
    // maybe think about a different solution here
    // 11644473600000 = diff between 1970 and 1601
    const timestamp = ((Date.now() + 11644473600000) * 10000).toString(16);
    const timestampLow = Number(
      `0x${timestamp.substring(Math.max(0, timestamp.length - 8))}`
    );
    const timestampHigh = Number(
      `0x${timestamp.substring(0, Math.max(0, timestamp.length - 8))}`
    );

    buf.writeUInt32LE(timestampLow, 24);
    buf.writeUInt32LE(timestampHigh, 28);

    // random client nonce
    buf.write(nonce || createPseudoRandomValue(16), 32, 'hex');

    // zero
    buf.writeUInt32LE(0, 40);

    // complete target information block from type 2 message
    targetInfoBuf.copy(buf, 44);

    // zero
    buf.writeUInt32LE(0, 44 + targetInfoBuf.length);

    hmac.update(buf.subarray(8));
    const hashedBuffer = hmac.digest();

    hashedBuffer.copy(buf);

    return buf;
  },

  /** @param {number} length */
  createPseudoRandomValue(length) {
    let str = '';
    while (str.length < length) {
      str += Math.floor(Math.random() * 16).toString(16);
    }
    return str;
  },
};
