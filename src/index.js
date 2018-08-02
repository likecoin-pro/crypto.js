import sha3 from 'js-sha3';
import KJUR from 'jsrsasign/lib/jsrsasign'

const BigInteger = KJUR.BigInteger;
const ECDSA = KJUR.crypto.ECDSA;
const shake256 = sha3.shake256;
const ecdsa = new ECDSA({curve: "secp256k1"});
const ecdsaKeyLen = ecdsa.ecparams.keylen / 4;

// redefine standard ECDSA-functions
ECDSA.biRSSigToASN1Sig = function (x, y) {
  return intToString(x) + intToString(y);
};

ECDSA.parseSigHex = function (signHex) {
  return {
    r: new BigInteger(signHex.substr(0, ecdsaKeyLen), 16),
    s: new BigInteger(signHex.substr(ecdsaKeyLen), 16)
  }
};

function trimHexPrefix(s) {
  return s.substr(0, 2) === "0x" ? s.substr(2) : s;
}

function hexToArray(s) {
  s = trimHexPrefix(s);
  const n = s.length >> 1;
  const a = new Array(n);
  for (let i = 0; i < n; i++) a[i] = parseInt(s.substr(i << 1, 2), 16);
  return a;
}

function newBigInt(s) {
  return new BigInteger(trimHexPrefix(s), 16);
}

function normInt(b) {
  return intToString(new BigInteger(b, 16).mod(ecdsa.ecparams.n).add(BigInteger.ONE));
}

function intToString(b) {
  return ("000000000000000" + b.toString(16)).slice(-ecdsaKeyLen);
}

function hash(data) {
  return shake256.create(256).update(data).toString();
}

function privateKeyBySecret(secret) {
  const prv = normInt(this.xhash(secret).toString().substr(0, ecdsaKeyLen));
  return "0x01" + intToString(prv);
}

function xhash(data) {
  const n = 200003;
  const a = new Array(n);
  for (let i = 0; i < n; i++) {
    data = shake256.create(256).update(data).array();
    a[i] = data.slice(-16);
  }
  a.sort(function (a, b) {
    for (let i = 0; i < 64; i++) if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
  });
  const h512 = shake256.create(512);
  for (let i = 0; i < n; i++) h512.update(a[i]);
  return h512.toString();
}

function publicKeyByPrivate(prv) {
  prv = trimHexPrefix(prv);
  if(prv.substr(0, 2) === "01") { // version
    prv = prv.substr(2);
  } else {
    throw "crypto: unknown format of private key";
  }
  const m = ecdsa.ecparams.G.multiply(new BigInteger(prv, 16));
  return "0x" + intToString(m.getX().toBigInteger()) + intToString(m.getY().toBigInteger());
}

function addressByPublic(pubHex) {
  let h = hexToArray(pubHex);
  h = shake256.create(512).update(h).array();
  h = shake256.create(512).update(h);
  return "0x" + h.toString().slice(-48);
}

const crypto = {
  hash,
  xhash,
  privateKeyBySecret,
  publicKeyByPrivate,
  addressByPublic
};

export default crypto;