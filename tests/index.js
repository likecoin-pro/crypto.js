const crypto = window.LikecoinCryptoJS;

describe("hash", function () {
    it("should generate hash for empty string", function () {
        const hash = crypto.hash("");
        expect(hash).toEqual("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    });
    it("should generate hash for 'abc' string", function () {
        const hash = crypto.hash("abc");
        expect(hash).toEqual("483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
    });
});

describe("xhash", function () {
    it("should generate hash for 'abc' string", function () {
        const hash = crypto.xhash("abc");
        expect(hash).toEqual("d85f68a0dd6b2ebeb5a60b47b70d2e4b63a842ac0510116e2d52f153e535cd60635f76fd52b34cceb671e0ed11093e923c39ee1a5ff32088ebf5f2415a285eef");
    });
});

describe("privateKeyBySecret", function () {
    it("should generate private key by secret for 'abc' string", function () {
        const privateKey = crypto.privateKeyBySecret("abc");
        expect(privateKey).toEqual("0xd85f68a0dd6b2ebeb5a60b47b70d2e4b63a842ac0510116e2d52f153e535cd61");
    });
});

describe("publicKeyByPrivate", function () {
    it("should generate public key from private", function () {
        const privateKey = crypto.privateKeyBySecret("abc");
        const publicKey = crypto.publicKeyByPrivate(privateKey);
        expect(publicKey).toEqual("0x022f86f8c408c20e8bdcef6471676a2157624915355fe662b568ac5e2a2a76fed5d34d4a184176a3e4a28bac7203a860510e363601f7c8f8657067173ed83f6e");
    });
});

describe("addressByPublic", function () {
    it("should return address from public key", function () {
        const privateKey = crypto.privateKeyBySecret("abc");
        const publicKey = crypto.publicKeyByPrivate(privateKey);
        const addrHex = crypto.addressByPublic(publicKey);
        expect(addrHex).toEqual("0x9a8a9d2b5766b5c3962f4dd301c01765bdc37a6387f24250");
    });
});