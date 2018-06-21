import sha3 from 'js-sha3';

import 'jsrsasign/ext/prng4';
import 'jsrsasign/ext/rng';
import 'jsrsasign/ext/jsbn';
import 'jsrsasign/src/ecdsa-modified-1.0';

const BigInteger = window.BigInteger;
const ECDSA = window.KJUR.crypto.ECDSA;

const shake256 = sha3.shake256;
const ecdsa = new ECDSA({curve: "secp256k1"});
const ecdsaKeyLen = ecdsa.ecparams.keylen / 4;

ECDSA.biRSSigToASN1Sig = function (x, y) {
    return ("000000000000000" + x.toString(16)).slice(-ecdsaKeyLen)
        + ("000000000000000" + y.toString(16)).slice(-ecdsaKeyLen);
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
    return new BigInteger(b, 16).mod(ecdsa.ecparams.n).add(BigInteger.ONE).toString(16);
}

function hash(data) {
    console.info('sss');
    return shake256.create(256).update(data).toString();
}

function privateKeyBySecret(secret) {
    return "0x" + normInt(xhash(secret).toString().substring(0, ecdsaKeyLen))
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
    const m = ecdsa.ecparams.G.multiply(newBigInt(prv));
    return "0x"
        + ("000000000000000" + m.getX().toBigInteger().toString(16)).slice(-ecdsaKeyLen)
        + ("000000000000000" + m.getY().toBigInteger().toString(16)).slice(-ecdsaKeyLen);
}

function addressByPublic(pubHex) {
    let h = hexToArray(pubHex);
    h = shake256.create(512).update(h).array();
    h = shake256.create(512).update(h);
    return "0x" + h.toString().slice(-48);
}

export {hash, xhash, privateKeyBySecret, publicKeyByPrivate, addressByPublic};