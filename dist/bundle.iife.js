var LikecoinCryptoJS = (function () {
	var commonjsGlobal = typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

	function createCommonjsModule(fn, module) {
		return module = { exports: {} }, fn(module, module.exports), module.exports;
	}

	var sha3 = createCommonjsModule(function (module) {
	/**
	 * [js-sha3]{@link https://github.com/emn178/js-sha3}
	 *
	 * @version 0.7.0
	 * @author Chen, Yi-Cyuan [emn178@gmail.com]
	 * @copyright Chen, Yi-Cyuan 2015-2017
	 * @license MIT
	 */
	/*jslint bitwise: true */
	(function () {

	  var ERROR = 'input is invalid type';
	  var WINDOW = typeof window === 'object';
	  var root = WINDOW ? window : {};
	  if (root.JS_SHA3_NO_WINDOW) {
	    WINDOW = false;
	  }
	  var WEB_WORKER = !WINDOW && typeof self === 'object';
	  var NODE_JS = !root.JS_SHA3_NO_NODE_JS && typeof process === 'object' && process.versions && process.versions.node;
	  if (NODE_JS) {
	    root = commonjsGlobal;
	  } else if (WEB_WORKER) {
	    root = self;
	  }
	  var COMMON_JS = !root.JS_SHA3_NO_COMMON_JS && 'object' === 'object' && module.exports;
	  var AMD = typeof undefined === 'function' && undefined.amd;
	  var ARRAY_BUFFER = !root.JS_SHA3_NO_ARRAY_BUFFER && typeof ArrayBuffer !== 'undefined';
	  var HEX_CHARS = '0123456789abcdef'.split('');
	  var SHAKE_PADDING = [31, 7936, 2031616, 520093696];
	  var CSHAKE_PADDING = [4, 1024, 262144, 67108864];
	  var KECCAK_PADDING = [1, 256, 65536, 16777216];
	  var PADDING = [6, 1536, 393216, 100663296];
	  var SHIFT = [0, 8, 16, 24];
	  var RC = [1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649,
	    0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0,
	    2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771,
	    2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648,
	    2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648];
	  var BITS = [224, 256, 384, 512];
	  var SHAKE_BITS = [128, 256];
	  var OUTPUT_TYPES = ['hex', 'buffer', 'arrayBuffer', 'array', 'digest'];
	  var CSHAKE_BYTEPAD = {
	    '128': 168,
	    '256': 136
	  };

	  if (root.JS_SHA3_NO_NODE_JS || !Array.isArray) {
	    Array.isArray = function (obj) {
	      return Object.prototype.toString.call(obj) === '[object Array]';
	    };
	  }

	  if (ARRAY_BUFFER && (root.JS_SHA3_NO_ARRAY_BUFFER_IS_VIEW || !ArrayBuffer.isView)) {
	    ArrayBuffer.isView = function (obj) {
	      return typeof obj === 'object' && obj.buffer && obj.buffer.constructor === ArrayBuffer;
	    };
	  }

	  var createOutputMethod = function (bits, padding, outputType) {
	    return function (message) {
	      return new Keccak(bits, padding, bits).update(message)[outputType]();
	    };
	  };

	  var createShakeOutputMethod = function (bits, padding, outputType) {
	    return function (message, outputBits) {
	      return new Keccak(bits, padding, outputBits).update(message)[outputType]();
	    };
	  };

	  var createCshakeOutputMethod = function (bits, padding, outputType) {
	    return function (message, outputBits, n, s) {
	      return methods['cshake' + bits].update(message, outputBits, n, s)[outputType]();
	    };
	  };

	  var createKmacOutputMethod = function (bits, padding, outputType) {
	    return function (key, message, outputBits, s) {
	      return methods['kmac' + bits].update(key, message, outputBits, s)[outputType]();
	    };
	  };

	  var createOutputMethods = function (method, createMethod, bits, padding) {
	    for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
	      var type = OUTPUT_TYPES[i];
	      method[type] = createMethod(bits, padding, type);
	    }
	    return method;
	  };

	  var createMethod = function (bits, padding) {
	    var method = createOutputMethod(bits, padding, 'hex');
	    method.create = function () {
	      return new Keccak(bits, padding, bits);
	    };
	    method.update = function (message) {
	      return method.create().update(message);
	    };
	    return createOutputMethods(method, createOutputMethod, bits, padding);
	  };

	  var createShakeMethod = function (bits, padding) {
	    var method = createShakeOutputMethod(bits, padding, 'hex');
	    method.create = function (outputBits) {
	      return new Keccak(bits, padding, outputBits);
	    };
	    method.update = function (message, outputBits) {
	      return method.create(outputBits).update(message);
	    };
	    return createOutputMethods(method, createShakeOutputMethod, bits, padding);
	  };

	  var createCshakeMethod = function (bits, padding) {
	    var w = CSHAKE_BYTEPAD[bits];
	    var method = createCshakeOutputMethod(bits, padding, 'hex');
	    method.create = function (outputBits, n, s) {
	      if (!n && !s) {
	        return methods['shake' + bits].create(outputBits);
	      } else {
	        return new Keccak(bits, padding, outputBits).bytepad([n, s], w);
	      }
	    };
	    method.update = function (message, outputBits, n, s) {
	      return method.create(outputBits, n, s).update(message);
	    };
	    return createOutputMethods(method, createCshakeOutputMethod, bits, padding);
	  };

	  var createKmacMethod = function (bits, padding) {
	    var w = CSHAKE_BYTEPAD[bits];
	    var method = createKmacOutputMethod(bits, padding, 'hex');
	    method.create = function (key, outputBits, s) {
	      return new Kmac(bits, padding, outputBits).bytepad(['KMAC', s], w).bytepad([key], w);
	    };
	    method.update = function (key, message, outputBits, s) {
	      return method.create(key, outputBits, s).update(message);
	    };
	    return createOutputMethods(method, createKmacOutputMethod, bits, padding);
	  };

	  var algorithms = [
	    { name: 'keccak', padding: KECCAK_PADDING, bits: BITS, createMethod: createMethod },
	    { name: 'sha3', padding: PADDING, bits: BITS, createMethod: createMethod },
	    { name: 'shake', padding: SHAKE_PADDING, bits: SHAKE_BITS, createMethod: createShakeMethod },
	    { name: 'cshake', padding: CSHAKE_PADDING, bits: SHAKE_BITS, createMethod: createCshakeMethod },
	    { name: 'kmac', padding: CSHAKE_PADDING, bits: SHAKE_BITS, createMethod: createKmacMethod }
	  ];

	  var methods = {}, methodNames = [];

	  for (var i = 0; i < algorithms.length; ++i) {
	    var algorithm = algorithms[i];
	    var bits = algorithm.bits;
	    for (var j = 0; j < bits.length; ++j) {
	      var methodName = algorithm.name + '_' + bits[j];
	      methodNames.push(methodName);
	      methods[methodName] = algorithm.createMethod(bits[j], algorithm.padding);
	      if (algorithm.name !== 'sha3') {
	        var newMethodName = algorithm.name + bits[j];
	        methodNames.push(newMethodName);
	        methods[newMethodName] = methods[methodName];
	      }
	    }
	  }

	  function Keccak(bits, padding, outputBits) {
	    this.blocks = [];
	    this.s = [];
	    this.padding = padding;
	    this.outputBits = outputBits;
	    this.reset = true;
	    this.finalized = false;
	    this.block = 0;
	    this.start = 0;
	    this.blockCount = (1600 - (bits << 1)) >> 5;
	    this.byteCount = this.blockCount << 2;
	    this.outputBlocks = outputBits >> 5;
	    this.extraBytes = (outputBits & 31) >> 3;

	    for (var i = 0; i < 50; ++i) {
	      this.s[i] = 0;
	    }
	  }

	  Keccak.prototype.update = function (message) {
	    if (this.finalized) {
	      return;
	    }
	    var notString, type = typeof message;
	    if (type !== 'string') {
	      if (type === 'object') {
	        if (message === null) {
	          throw ERROR;
	        } else if (ARRAY_BUFFER && message.constructor === ArrayBuffer) {
	          message = new Uint8Array(message);
	        } else if (!Array.isArray(message)) {
	          if (!ARRAY_BUFFER || !ArrayBuffer.isView(message)) {
	            throw ERROR;
	          }
	        }
	      } else {
	        throw ERROR;
	      }
	      notString = true;
	    }
	    var blocks = this.blocks, byteCount = this.byteCount, length = message.length,
	      blockCount = this.blockCount, index = 0, s = this.s, i, code;

	    while (index < length) {
	      if (this.reset) {
	        this.reset = false;
	        blocks[0] = this.block;
	        for (i = 1; i < blockCount + 1; ++i) {
	          blocks[i] = 0;
	        }
	      }
	      if (notString) {
	        for (i = this.start; index < length && i < byteCount; ++index) {
	          blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
	        }
	      } else {
	        for (i = this.start; index < length && i < byteCount; ++index) {
	          code = message.charCodeAt(index);
	          if (code < 0x80) {
	            blocks[i >> 2] |= code << SHIFT[i++ & 3];
	          } else if (code < 0x800) {
	            blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
	            blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
	          } else if (code < 0xd800 || code >= 0xe000) {
	            blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
	            blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
	            blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
	          } else {
	            code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
	            blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
	            blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) << SHIFT[i++ & 3];
	            blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
	            blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
	          }
	        }
	      }
	      this.lastByteIndex = i;
	      if (i >= byteCount) {
	        this.start = i - byteCount;
	        this.block = blocks[blockCount];
	        for (i = 0; i < blockCount; ++i) {
	          s[i] ^= blocks[i];
	        }
	        f(s);
	        this.reset = true;
	      } else {
	        this.start = i;
	      }
	    }
	    return this;
	  };

	  Keccak.prototype.encode = function (x, right) {
	    var o = x & 255, n = 1;
	    var bytes = [o];
	    x = x >> 8;
	    o = x & 255;
	    while (o > 0) {
	      bytes.unshift(o);
	      x = x >> 8;
	      o = x & 255;
	      ++n;
	    }
	    if (right) {
	      bytes.push(n);
	    } else {
	      bytes.unshift(n);
	    }
	    this.update(bytes);
	    return bytes.length;
	  };

	  Keccak.prototype.encodeString = function (str) {
	    var notString, type = typeof str;
	    if (type !== 'string') {
	      if (type === 'object') {
	        if (str === null) {
	          throw ERROR;
	        } else if (ARRAY_BUFFER && str.constructor === ArrayBuffer) {
	          str = new Uint8Array(str);
	        } else if (!Array.isArray(str)) {
	          if (!ARRAY_BUFFER || !ArrayBuffer.isView(str)) {
	            throw ERROR;
	          }
	        }
	      } else {
	        throw ERROR;
	      }
	      notString = true;
	    }
	    var bytes = 0, length = str.length;
	    if (notString) {
	      bytes = length;
	    } else {
	      for (var i = 0; i < str.length; ++i) {
	        var code = str.charCodeAt(i);
	        if (code < 0x80) {
	          bytes += 1;
	        } else if (code < 0x800) {
	          bytes += 2;
	        } else if (code < 0xd800 || code >= 0xe000) {
	          bytes += 3;
	        } else {
	          code = 0x10000 + (((code & 0x3ff) << 10) | (str.charCodeAt(++i) & 0x3ff));
	          bytes += 4;
	        }
	      }
	    }
	    bytes += this.encode(bytes * 8);
	    this.update(str);
	    return bytes;
	  };

	  Keccak.prototype.bytepad = function (strs, w) {
	    var bytes = this.encode(w);
	    for (var i = 0; i < strs.length; ++i) {
	      bytes += this.encodeString(strs[i]);
	    }
	    var paddingBytes = w - bytes % w;
	    var zeros = [];
	    zeros.length = paddingBytes;
	    this.update(zeros);
	    return this;
	  };

	  Keccak.prototype.finalize = function () {
	    if (this.finalized) {
	      return;
	    }
	    this.finalized = true;
	    var blocks = this.blocks, i = this.lastByteIndex, blockCount = this.blockCount, s = this.s;
	    blocks[i >> 2] |= this.padding[i & 3];
	    if (this.lastByteIndex === this.byteCount) {
	      blocks[0] = blocks[blockCount];
	      for (i = 1; i < blockCount + 1; ++i) {
	        blocks[i] = 0;
	      }
	    }
	    blocks[blockCount - 1] |= 0x80000000;
	    for (i = 0; i < blockCount; ++i) {
	      s[i] ^= blocks[i];
	    }
	    f(s);
	  };

	  Keccak.prototype.toString = Keccak.prototype.hex = function () {
	    this.finalize();

	    var blockCount = this.blockCount, s = this.s, outputBlocks = this.outputBlocks,
	      extraBytes = this.extraBytes, i = 0, j = 0;
	    var hex = '', block;
	    while (j < outputBlocks) {
	      for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
	        block = s[i];
	        hex += HEX_CHARS[(block >> 4) & 0x0F] + HEX_CHARS[block & 0x0F] +
	          HEX_CHARS[(block >> 12) & 0x0F] + HEX_CHARS[(block >> 8) & 0x0F] +
	          HEX_CHARS[(block >> 20) & 0x0F] + HEX_CHARS[(block >> 16) & 0x0F] +
	          HEX_CHARS[(block >> 28) & 0x0F] + HEX_CHARS[(block >> 24) & 0x0F];
	      }
	      if (j % blockCount === 0) {
	        f(s);
	        i = 0;
	      }
	    }
	    if (extraBytes) {
	      block = s[i];
	      hex += HEX_CHARS[(block >> 4) & 0x0F] + HEX_CHARS[block & 0x0F];
	      if (extraBytes > 1) {
	        hex += HEX_CHARS[(block >> 12) & 0x0F] + HEX_CHARS[(block >> 8) & 0x0F];
	      }
	      if (extraBytes > 2) {
	        hex += HEX_CHARS[(block >> 20) & 0x0F] + HEX_CHARS[(block >> 16) & 0x0F];
	      }
	    }
	    return hex;
	  };

	  Keccak.prototype.arrayBuffer = function () {
	    this.finalize();

	    var blockCount = this.blockCount, s = this.s, outputBlocks = this.outputBlocks,
	      extraBytes = this.extraBytes, i = 0, j = 0;
	    var bytes = this.outputBits >> 3;
	    var buffer;
	    if (extraBytes) {
	      buffer = new ArrayBuffer((outputBlocks + 1) << 2);
	    } else {
	      buffer = new ArrayBuffer(bytes);
	    }
	    var array = new Uint32Array(buffer);
	    while (j < outputBlocks) {
	      for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
	        array[j] = s[i];
	      }
	      if (j % blockCount === 0) {
	        f(s);
	      }
	    }
	    if (extraBytes) {
	      array[i] = s[i];
	      buffer = buffer.slice(0, bytes);
	    }
	    return buffer;
	  };

	  Keccak.prototype.buffer = Keccak.prototype.arrayBuffer;

	  Keccak.prototype.digest = Keccak.prototype.array = function () {
	    this.finalize();

	    var blockCount = this.blockCount, s = this.s, outputBlocks = this.outputBlocks,
	      extraBytes = this.extraBytes, i = 0, j = 0;
	    var array = [], offset, block;
	    while (j < outputBlocks) {
	      for (i = 0; i < blockCount && j < outputBlocks; ++i, ++j) {
	        offset = j << 2;
	        block = s[i];
	        array[offset] = block & 0xFF;
	        array[offset + 1] = (block >> 8) & 0xFF;
	        array[offset + 2] = (block >> 16) & 0xFF;
	        array[offset + 3] = (block >> 24) & 0xFF;
	      }
	      if (j % blockCount === 0) {
	        f(s);
	      }
	    }
	    if (extraBytes) {
	      offset = j << 2;
	      block = s[i];
	      array[offset] = block & 0xFF;
	      if (extraBytes > 1) {
	        array[offset + 1] = (block >> 8) & 0xFF;
	      }
	      if (extraBytes > 2) {
	        array[offset + 2] = (block >> 16) & 0xFF;
	      }
	    }
	    return array;
	  };

	  function Kmac(bits, padding, outputBits) {
	    Keccak.call(this, bits, padding, outputBits);
	  }

	  Kmac.prototype = new Keccak();

	  Kmac.prototype.finalize = function () {
	    this.encode(this.outputBits, true);
	    return Keccak.prototype.finalize.call(this);
	  };

	  var f = function (s) {
	    var h, l, n, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9,
	      b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17,
	      b18, b19, b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31, b32, b33,
	      b34, b35, b36, b37, b38, b39, b40, b41, b42, b43, b44, b45, b46, b47, b48, b49;
	    for (n = 0; n < 48; n += 2) {
	      c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
	      c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
	      c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
	      c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
	      c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
	      c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
	      c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
	      c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
	      c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
	      c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49];

	      h = c8 ^ ((c2 << 1) | (c3 >>> 31));
	      l = c9 ^ ((c3 << 1) | (c2 >>> 31));
	      s[0] ^= h;
	      s[1] ^= l;
	      s[10] ^= h;
	      s[11] ^= l;
	      s[20] ^= h;
	      s[21] ^= l;
	      s[30] ^= h;
	      s[31] ^= l;
	      s[40] ^= h;
	      s[41] ^= l;
	      h = c0 ^ ((c4 << 1) | (c5 >>> 31));
	      l = c1 ^ ((c5 << 1) | (c4 >>> 31));
	      s[2] ^= h;
	      s[3] ^= l;
	      s[12] ^= h;
	      s[13] ^= l;
	      s[22] ^= h;
	      s[23] ^= l;
	      s[32] ^= h;
	      s[33] ^= l;
	      s[42] ^= h;
	      s[43] ^= l;
	      h = c2 ^ ((c6 << 1) | (c7 >>> 31));
	      l = c3 ^ ((c7 << 1) | (c6 >>> 31));
	      s[4] ^= h;
	      s[5] ^= l;
	      s[14] ^= h;
	      s[15] ^= l;
	      s[24] ^= h;
	      s[25] ^= l;
	      s[34] ^= h;
	      s[35] ^= l;
	      s[44] ^= h;
	      s[45] ^= l;
	      h = c4 ^ ((c8 << 1) | (c9 >>> 31));
	      l = c5 ^ ((c9 << 1) | (c8 >>> 31));
	      s[6] ^= h;
	      s[7] ^= l;
	      s[16] ^= h;
	      s[17] ^= l;
	      s[26] ^= h;
	      s[27] ^= l;
	      s[36] ^= h;
	      s[37] ^= l;
	      s[46] ^= h;
	      s[47] ^= l;
	      h = c6 ^ ((c0 << 1) | (c1 >>> 31));
	      l = c7 ^ ((c1 << 1) | (c0 >>> 31));
	      s[8] ^= h;
	      s[9] ^= l;
	      s[18] ^= h;
	      s[19] ^= l;
	      s[28] ^= h;
	      s[29] ^= l;
	      s[38] ^= h;
	      s[39] ^= l;
	      s[48] ^= h;
	      s[49] ^= l;

	      b0 = s[0];
	      b1 = s[1];
	      b32 = (s[11] << 4) | (s[10] >>> 28);
	      b33 = (s[10] << 4) | (s[11] >>> 28);
	      b14 = (s[20] << 3) | (s[21] >>> 29);
	      b15 = (s[21] << 3) | (s[20] >>> 29);
	      b46 = (s[31] << 9) | (s[30] >>> 23);
	      b47 = (s[30] << 9) | (s[31] >>> 23);
	      b28 = (s[40] << 18) | (s[41] >>> 14);
	      b29 = (s[41] << 18) | (s[40] >>> 14);
	      b20 = (s[2] << 1) | (s[3] >>> 31);
	      b21 = (s[3] << 1) | (s[2] >>> 31);
	      b2 = (s[13] << 12) | (s[12] >>> 20);
	      b3 = (s[12] << 12) | (s[13] >>> 20);
	      b34 = (s[22] << 10) | (s[23] >>> 22);
	      b35 = (s[23] << 10) | (s[22] >>> 22);
	      b16 = (s[33] << 13) | (s[32] >>> 19);
	      b17 = (s[32] << 13) | (s[33] >>> 19);
	      b48 = (s[42] << 2) | (s[43] >>> 30);
	      b49 = (s[43] << 2) | (s[42] >>> 30);
	      b40 = (s[5] << 30) | (s[4] >>> 2);
	      b41 = (s[4] << 30) | (s[5] >>> 2);
	      b22 = (s[14] << 6) | (s[15] >>> 26);
	      b23 = (s[15] << 6) | (s[14] >>> 26);
	      b4 = (s[25] << 11) | (s[24] >>> 21);
	      b5 = (s[24] << 11) | (s[25] >>> 21);
	      b36 = (s[34] << 15) | (s[35] >>> 17);
	      b37 = (s[35] << 15) | (s[34] >>> 17);
	      b18 = (s[45] << 29) | (s[44] >>> 3);
	      b19 = (s[44] << 29) | (s[45] >>> 3);
	      b10 = (s[6] << 28) | (s[7] >>> 4);
	      b11 = (s[7] << 28) | (s[6] >>> 4);
	      b42 = (s[17] << 23) | (s[16] >>> 9);
	      b43 = (s[16] << 23) | (s[17] >>> 9);
	      b24 = (s[26] << 25) | (s[27] >>> 7);
	      b25 = (s[27] << 25) | (s[26] >>> 7);
	      b6 = (s[36] << 21) | (s[37] >>> 11);
	      b7 = (s[37] << 21) | (s[36] >>> 11);
	      b38 = (s[47] << 24) | (s[46] >>> 8);
	      b39 = (s[46] << 24) | (s[47] >>> 8);
	      b30 = (s[8] << 27) | (s[9] >>> 5);
	      b31 = (s[9] << 27) | (s[8] >>> 5);
	      b12 = (s[18] << 20) | (s[19] >>> 12);
	      b13 = (s[19] << 20) | (s[18] >>> 12);
	      b44 = (s[29] << 7) | (s[28] >>> 25);
	      b45 = (s[28] << 7) | (s[29] >>> 25);
	      b26 = (s[38] << 8) | (s[39] >>> 24);
	      b27 = (s[39] << 8) | (s[38] >>> 24);
	      b8 = (s[48] << 14) | (s[49] >>> 18);
	      b9 = (s[49] << 14) | (s[48] >>> 18);

	      s[0] = b0 ^ (~b2 & b4);
	      s[1] = b1 ^ (~b3 & b5);
	      s[10] = b10 ^ (~b12 & b14);
	      s[11] = b11 ^ (~b13 & b15);
	      s[20] = b20 ^ (~b22 & b24);
	      s[21] = b21 ^ (~b23 & b25);
	      s[30] = b30 ^ (~b32 & b34);
	      s[31] = b31 ^ (~b33 & b35);
	      s[40] = b40 ^ (~b42 & b44);
	      s[41] = b41 ^ (~b43 & b45);
	      s[2] = b2 ^ (~b4 & b6);
	      s[3] = b3 ^ (~b5 & b7);
	      s[12] = b12 ^ (~b14 & b16);
	      s[13] = b13 ^ (~b15 & b17);
	      s[22] = b22 ^ (~b24 & b26);
	      s[23] = b23 ^ (~b25 & b27);
	      s[32] = b32 ^ (~b34 & b36);
	      s[33] = b33 ^ (~b35 & b37);
	      s[42] = b42 ^ (~b44 & b46);
	      s[43] = b43 ^ (~b45 & b47);
	      s[4] = b4 ^ (~b6 & b8);
	      s[5] = b5 ^ (~b7 & b9);
	      s[14] = b14 ^ (~b16 & b18);
	      s[15] = b15 ^ (~b17 & b19);
	      s[24] = b24 ^ (~b26 & b28);
	      s[25] = b25 ^ (~b27 & b29);
	      s[34] = b34 ^ (~b36 & b38);
	      s[35] = b35 ^ (~b37 & b39);
	      s[44] = b44 ^ (~b46 & b48);
	      s[45] = b45 ^ (~b47 & b49);
	      s[6] = b6 ^ (~b8 & b0);
	      s[7] = b7 ^ (~b9 & b1);
	      s[16] = b16 ^ (~b18 & b10);
	      s[17] = b17 ^ (~b19 & b11);
	      s[26] = b26 ^ (~b28 & b20);
	      s[27] = b27 ^ (~b29 & b21);
	      s[36] = b36 ^ (~b38 & b30);
	      s[37] = b37 ^ (~b39 & b31);
	      s[46] = b46 ^ (~b48 & b40);
	      s[47] = b47 ^ (~b49 & b41);
	      s[8] = b8 ^ (~b0 & b2);
	      s[9] = b9 ^ (~b1 & b3);
	      s[18] = b18 ^ (~b10 & b12);
	      s[19] = b19 ^ (~b11 & b13);
	      s[28] = b28 ^ (~b20 & b22);
	      s[29] = b29 ^ (~b21 & b23);
	      s[38] = b38 ^ (~b30 & b32);
	      s[39] = b39 ^ (~b31 & b33);
	      s[48] = b48 ^ (~b40 & b42);
	      s[49] = b49 ^ (~b41 & b43);

	      s[0] ^= RC[n];
	      s[1] ^= RC[n + 1];
	    }
	  };

	  if (COMMON_JS) {
	    module.exports = methods;
	  } else {
	    for (i = 0; i < methodNames.length; ++i) {
	      root[methodNames[i]] = methods[methodNames[i]];
	    }
	    if (AMD) {
	      undefined(function () {
	        return methods;
	      });
	    }
	  }
	})();
	});

	/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
	 */

	/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
	 */
	var rng_pool;
	var rng_pptr;

	// Mix in a 32-bit integer into the pool
	function rng_seed_int(x) {
	  rng_pool[rng_pptr++] ^= x & 255;
	  rng_pool[rng_pptr++] ^= (x >> 8) & 255;
	  rng_pool[rng_pptr++] ^= (x >> 16) & 255;
	  rng_pool[rng_pptr++] ^= (x >> 24) & 255;
	  if(rng_pptr >= rng_psize) rng_pptr -= rng_psize;
	}

	// Mix in the current time (w/milliseconds) into the pool
	function rng_seed_time() {
	  rng_seed_int(new Date().getTime());
	}

	// Initialize the pool with junk if needed.
	if (rng_pool == null) {
	  rng_pool = new Array();
	  rng_pptr = 0;
	  var t;
	  if (window !== undefined &&
	      (window.crypto !== undefined ||
	       window.msCrypto !== undefined)) {
	    var crypto = window.crypto || window.msCrypto;
	    if (crypto.getRandomValues) {
	      // Use webcrypto if available
	      var ua = new Uint8Array(32);
	      crypto.getRandomValues(ua);
	      for(t = 0; t < 32; ++t)
	        rng_pool[rng_pptr++] = ua[t];
	    } else if (navigator.appName == "Netscape" && navigator.appVersion < "5") {
	      // Extract entropy (256 bits) from NS4 RNG if available
	      var z = window.crypto.random(32);
	      for(t = 0; t < z.length; ++t)
	        rng_pool[rng_pptr++] = z.charCodeAt(t) & 255;
	    }
	  }  
	  while (rng_pptr < rng_psize) {  // extract some randomness from Math.random()
	    t = Math.floor(65536 * Math.random());
	    rng_pool[rng_pptr++] = t >>> 8;
	    rng_pool[rng_pptr++] = t & 255;
	  }
	  rng_pptr = 0;
	  rng_seed_time();
	  //rng_seed_int(window.screenX);
	  //rng_seed_int(window.screenY);
	}

	/*! (c) Tom Wu | http://www-cs-students.stanford.edu/~tjw/jsbn/
	 */
	// Copyright (c) 2005  Tom Wu
	// All Rights Reserved.
	// See "LICENSE" for details.

	// Basic JavaScript BN library - subset useful for RSA encryption.

	// Bits per digit
	var dbits;

	// (public) Constructor
	function BigInteger$1(a,b,c) {
	  if(a != null)
	    if("number" == typeof a) this.fromNumber(a,b,c);
	    else if(b == null && "string" != typeof a) this.fromString(a,256);
	    else this.fromString(a,b);
	}

	// return new, unset BigInteger
	function nbi() { return new BigInteger$1(null); }

	// am: Compute w_j += (x*this_i), propagate carries,
	// c is initial carry, returns final carry.
	// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
	// We need to select the fastest one that works in this environment.

	// am1: use a single mult and divide to get the high bits,
	// max digit bits should be 26 because
	// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
	function am1(i,x,w,j,c,n) {
	  while(--n >= 0) {
	    var v = x*this[i++]+w[j]+c;
	    c = Math.floor(v/0x4000000);
	    w[j++] = v&0x3ffffff;
	  }
	  return c;
	}
	// am2 avoids a big mult-and-extract completely.
	// Max digit bits should be <= 30 because we do bitwise ops
	// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
	function am2(i,x,w,j,c,n) {
	  var xl = x&0x7fff, xh = x>>15;
	  while(--n >= 0) {
	    var l = this[i]&0x7fff;
	    var h = this[i++]>>15;
	    var m = xh*l+h*xl;
	    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
	    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
	    w[j++] = l&0x3fffffff;
	  }
	  return c;
	}
	// Alternately, set max digit bits to 28 since some
	// browsers slow down when dealing with 32-bit numbers.
	function am3(i,x,w,j,c,n) {
	  var xl = x&0x3fff, xh = x>>14;
	  while(--n >= 0) {
	    var l = this[i]&0x3fff;
	    var h = this[i++]>>14;
	    var m = xh*l+h*xl;
	    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
	    c = (l>>28)+(m>>14)+xh*h;
	    w[j++] = l&0xfffffff;
	  }
	  return c;
	}
	if(navigator.appName == "Microsoft Internet Explorer") {
	  BigInteger$1.prototype.am = am2;
	  dbits = 30;
	}
	else if(navigator.appName != "Netscape") {
	  BigInteger$1.prototype.am = am1;
	  dbits = 26;
	}
	else { // Mozilla/Netscape seems to prefer am3
	  BigInteger$1.prototype.am = am3;
	  dbits = 28;
	}

	BigInteger$1.prototype.DB = dbits;
	BigInteger$1.prototype.DM = ((1<<dbits)-1);
	BigInteger$1.prototype.DV = (1<<dbits);

	var BI_FP = 52;
	BigInteger$1.prototype.FV = Math.pow(2,BI_FP);
	BigInteger$1.prototype.F1 = BI_FP-dbits;
	BigInteger$1.prototype.F2 = 2*dbits-BI_FP;

	// Digit conversions
	var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
	var BI_RC = new Array();
	var rr,vv;
	rr = "0".charCodeAt(0);
	for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
	rr = "a".charCodeAt(0);
	for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
	rr = "A".charCodeAt(0);
	for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

	function int2char(n) { return BI_RM.charAt(n); }
	function intAt(s,i) {
	  var c = BI_RC[s.charCodeAt(i)];
	  return (c==null)?-1:c;
	}

	// (protected) copy this to r
	function bnpCopyTo(r) {
	  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
	  r.t = this.t;
	  r.s = this.s;
	}

	// (protected) set from integer value x, -DV <= x < DV
	function bnpFromInt(x) {
	  this.t = 1;
	  this.s = (x<0)?-1:0;
	  if(x > 0) this[0] = x;
	  else if(x < -1) this[0] = x+this.DV;
	  else this.t = 0;
	}

	// return bigint initialized to value
	function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

	// (protected) set from string and radix
	function bnpFromString(s,b) {
	  var k;
	  if(b == 16) k = 4;
	  else if(b == 8) k = 3;
	  else if(b == 256) k = 8; // byte array
	  else if(b == 2) k = 1;
	  else if(b == 32) k = 5;
	  else if(b == 4) k = 2;
	  else { this.fromRadix(s,b); return; }
	  this.t = 0;
	  this.s = 0;
	  var i = s.length, mi = false, sh = 0;
	  while(--i >= 0) {
	    var x = (k==8)?s[i]&0xff:intAt(s,i);
	    if(x < 0) {
	      if(s.charAt(i) == "-") mi = true;
	      continue;
	    }
	    mi = false;
	    if(sh == 0)
	      this[this.t++] = x;
	    else if(sh+k > this.DB) {
	      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
	      this[this.t++] = (x>>(this.DB-sh));
	    }
	    else
	      this[this.t-1] |= x<<sh;
	    sh += k;
	    if(sh >= this.DB) sh -= this.DB;
	  }
	  if(k == 8 && (s[0]&0x80) != 0) {
	    this.s = -1;
	    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
	  }
	  this.clamp();
	  if(mi) BigInteger$1.ZERO.subTo(this,this);
	}

	// (protected) clamp off excess high words
	function bnpClamp() {
	  var c = this.s&this.DM;
	  while(this.t > 0 && this[this.t-1] == c) --this.t;
	}

	// (public) return string representation in given radix
	function bnToString(b) {
	  if(this.s < 0) return "-"+this.negate().toString(b);
	  var k;
	  if(b == 16) k = 4;
	  else if(b == 8) k = 3;
	  else if(b == 2) k = 1;
	  else if(b == 32) k = 5;
	  else if(b == 4) k = 2;
	  else return this.toRadix(b);
	  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
	  var p = this.DB-(i*this.DB)%k;
	  if(i-- > 0) {
	    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
	    while(i >= 0) {
	      if(p < k) {
	        d = (this[i]&((1<<p)-1))<<(k-p);
	        d |= this[--i]>>(p+=this.DB-k);
	      }
	      else {
	        d = (this[i]>>(p-=k))&km;
	        if(p <= 0) { p += this.DB; --i; }
	      }
	      if(d > 0) m = true;
	      if(m) r += int2char(d);
	    }
	  }
	  return m?r:"0";
	}

	// (public) -this
	function bnNegate() { var r = nbi(); BigInteger$1.ZERO.subTo(this,r); return r; }

	// (public) |this|
	function bnAbs() { return (this.s<0)?this.negate():this; }

	// (public) return + if this > a, - if this < a, 0 if equal
	function bnCompareTo(a) {
	  var r = this.s-a.s;
	  if(r != 0) return r;
	  var i = this.t;
	  r = i-a.t;
	  if(r != 0) return (this.s<0)?-r:r;
	  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
	  return 0;
	}

	// returns bit length of the integer x
	function nbits(x) {
	  var r = 1, t;
	  if((t=x>>>16) != 0) { x = t; r += 16; }
	  if((t=x>>8) != 0) { x = t; r += 8; }
	  if((t=x>>4) != 0) { x = t; r += 4; }
	  if((t=x>>2) != 0) { x = t; r += 2; }
	  if((t=x>>1) != 0) { x = t; r += 1; }
	  return r;
	}

	// (public) return the number of bits in "this"
	function bnBitLength() {
	  if(this.t <= 0) return 0;
	  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
	}

	// (protected) r = this << n*DB
	function bnpDLShiftTo(n,r) {
	  var i;
	  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
	  for(i = n-1; i >= 0; --i) r[i] = 0;
	  r.t = this.t+n;
	  r.s = this.s;
	}

	// (protected) r = this >> n*DB
	function bnpDRShiftTo(n,r) {
	  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
	  r.t = Math.max(this.t-n,0);
	  r.s = this.s;
	}

	// (protected) r = this << n
	function bnpLShiftTo(n,r) {
	  var bs = n%this.DB;
	  var cbs = this.DB-bs;
	  var bm = (1<<cbs)-1;
	  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
	  for(i = this.t-1; i >= 0; --i) {
	    r[i+ds+1] = (this[i]>>cbs)|c;
	    c = (this[i]&bm)<<bs;
	  }
	  for(i = ds-1; i >= 0; --i) r[i] = 0;
	  r[ds] = c;
	  r.t = this.t+ds+1;
	  r.s = this.s;
	  r.clamp();
	}

	// (protected) r = this >> n
	function bnpRShiftTo(n,r) {
	  r.s = this.s;
	  var ds = Math.floor(n/this.DB);
	  if(ds >= this.t) { r.t = 0; return; }
	  var bs = n%this.DB;
	  var cbs = this.DB-bs;
	  var bm = (1<<bs)-1;
	  r[0] = this[ds]>>bs;
	  for(var i = ds+1; i < this.t; ++i) {
	    r[i-ds-1] |= (this[i]&bm)<<cbs;
	    r[i-ds] = this[i]>>bs;
	  }
	  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
	  r.t = this.t-ds;
	  r.clamp();
	}

	// (protected) r = this - a
	function bnpSubTo(a,r) {
	  var i = 0, c = 0, m = Math.min(a.t,this.t);
	  while(i < m) {
	    c += this[i]-a[i];
	    r[i++] = c&this.DM;
	    c >>= this.DB;
	  }
	  if(a.t < this.t) {
	    c -= a.s;
	    while(i < this.t) {
	      c += this[i];
	      r[i++] = c&this.DM;
	      c >>= this.DB;
	    }
	    c += this.s;
	  }
	  else {
	    c += this.s;
	    while(i < a.t) {
	      c -= a[i];
	      r[i++] = c&this.DM;
	      c >>= this.DB;
	    }
	    c -= a.s;
	  }
	  r.s = (c<0)?-1:0;
	  if(c < -1) r[i++] = this.DV+c;
	  else if(c > 0) r[i++] = c;
	  r.t = i;
	  r.clamp();
	}

	// (protected) r = this * a, r != this,a (HAC 14.12)
	// "this" should be the larger one if appropriate.
	function bnpMultiplyTo(a,r) {
	  var x = this.abs(), y = a.abs();
	  var i = x.t;
	  r.t = i+y.t;
	  while(--i >= 0) r[i] = 0;
	  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
	  r.s = 0;
	  r.clamp();
	  if(this.s != a.s) BigInteger$1.ZERO.subTo(r,r);
	}

	// (protected) r = this^2, r != this (HAC 14.16)
	function bnpSquareTo(r) {
	  var x = this.abs();
	  var i = r.t = 2*x.t;
	  while(--i >= 0) r[i] = 0;
	  for(i = 0; i < x.t-1; ++i) {
	    var c = x.am(i,x[i],r,2*i,0,1);
	    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
	      r[i+x.t] -= x.DV;
	      r[i+x.t+1] = 1;
	    }
	  }
	  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
	  r.s = 0;
	  r.clamp();
	}

	// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
	// r != q, this != m.  q or r may be null.
	function bnpDivRemTo(m,q,r) {
	  var pm = m.abs();
	  if(pm.t <= 0) return;
	  var pt = this.abs();
	  if(pt.t < pm.t) {
	    if(q != null) q.fromInt(0);
	    if(r != null) this.copyTo(r);
	    return;
	  }
	  if(r == null) r = nbi();
	  var y = nbi(), ts = this.s, ms = m.s;
	  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
	  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
	  else { pm.copyTo(y); pt.copyTo(r); }
	  var ys = y.t;
	  var y0 = y[ys-1];
	  if(y0 == 0) return;
	  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
	  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
	  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
	  y.dlShiftTo(j,t);
	  if(r.compareTo(t) >= 0) {
	    r[r.t++] = 1;
	    r.subTo(t,r);
	  }
	  BigInteger$1.ONE.dlShiftTo(ys,t);
	  t.subTo(y,y);	// "negative" y so we can replace sub with am later
	  while(y.t < ys) y[y.t++] = 0;
	  while(--j >= 0) {
	    // Estimate quotient digit
	    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
	    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
	      y.dlShiftTo(j,t);
	      r.subTo(t,r);
	      while(r[i] < --qd) r.subTo(t,r);
	    }
	  }
	  if(q != null) {
	    r.drShiftTo(ys,q);
	    if(ts != ms) BigInteger$1.ZERO.subTo(q,q);
	  }
	  r.t = ys;
	  r.clamp();
	  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
	  if(ts < 0) BigInteger$1.ZERO.subTo(r,r);
	}

	// (public) this mod a
	function bnMod(a) {
	  var r = nbi();
	  this.abs().divRemTo(a,null,r);
	  if(this.s < 0 && r.compareTo(BigInteger$1.ZERO) > 0) a.subTo(r,r);
	  return r;
	}

	// Modular reduction using "classic" algorithm
	function Classic(m) { this.m = m; }
	function cConvert(x) {
	  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
	  else return x;
	}
	function cRevert(x) { return x; }
	function cReduce(x) { x.divRemTo(this.m,null,x); }
	function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
	function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

	Classic.prototype.convert = cConvert;
	Classic.prototype.revert = cRevert;
	Classic.prototype.reduce = cReduce;
	Classic.prototype.mulTo = cMulTo;
	Classic.prototype.sqrTo = cSqrTo;

	// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
	// justification:
	//         xy == 1 (mod m)
	//         xy =  1+km
	//   xy(2-xy) = (1+km)(1-km)
	// x[y(2-xy)] = 1-k^2m^2
	// x[y(2-xy)] == 1 (mod m^2)
	// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
	// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
	// JS multiply "overflows" differently from C/C++, so care is needed here.
	function bnpInvDigit() {
	  if(this.t < 1) return 0;
	  var x = this[0];
	  if((x&1) == 0) return 0;
	  var y = x&3;		// y == 1/x mod 2^2
	  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
	  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
	  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
	  // last step - calculate inverse mod DV directly;
	  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
	  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
	  // we really want the negative inverse, and -DV < y < DV
	  return (y>0)?this.DV-y:-y;
	}

	// Montgomery reduction
	function Montgomery(m) {
	  this.m = m;
	  this.mp = m.invDigit();
	  this.mpl = this.mp&0x7fff;
	  this.mph = this.mp>>15;
	  this.um = (1<<(m.DB-15))-1;
	  this.mt2 = 2*m.t;
	}

	// xR mod m
	function montConvert(x) {
	  var r = nbi();
	  x.abs().dlShiftTo(this.m.t,r);
	  r.divRemTo(this.m,null,r);
	  if(x.s < 0 && r.compareTo(BigInteger$1.ZERO) > 0) this.m.subTo(r,r);
	  return r;
	}

	// x/R mod m
	function montRevert(x) {
	  var r = nbi();
	  x.copyTo(r);
	  this.reduce(r);
	  return r;
	}

	// x = x/R mod m (HAC 14.32)
	function montReduce(x) {
	  while(x.t <= this.mt2)	// pad x so am has enough room later
	    x[x.t++] = 0;
	  for(var i = 0; i < this.m.t; ++i) {
	    // faster way of calculating u0 = x[i]*mp mod DV
	    var j = x[i]&0x7fff;
	    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
	    // use am to combine the multiply-shift-add into one call
	    j = i+this.m.t;
	    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
	    // propagate carry
	    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
	  }
	  x.clamp();
	  x.drShiftTo(this.m.t,x);
	  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
	}

	// r = "x^2/R mod m"; x != r
	function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

	// r = "xy/R mod m"; x,y != r
	function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

	Montgomery.prototype.convert = montConvert;
	Montgomery.prototype.revert = montRevert;
	Montgomery.prototype.reduce = montReduce;
	Montgomery.prototype.mulTo = montMulTo;
	Montgomery.prototype.sqrTo = montSqrTo;

	// (protected) true iff this is even
	function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

	// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
	function bnpExp(e,z) {
	  if(e > 0xffffffff || e < 1) return BigInteger$1.ONE;
	  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
	  g.copyTo(r);
	  while(--i >= 0) {
	    z.sqrTo(r,r2);
	    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
	    else { var t = r; r = r2; r2 = t; }
	  }
	  return z.revert(r);
	}

	// (public) this^e % m, 0 <= e < 2^32
	function bnModPowInt(e,m) {
	  var z;
	  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
	  return this.exp(e,z);
	}

	// protected
	BigInteger$1.prototype.copyTo = bnpCopyTo;
	BigInteger$1.prototype.fromInt = bnpFromInt;
	BigInteger$1.prototype.fromString = bnpFromString;
	BigInteger$1.prototype.clamp = bnpClamp;
	BigInteger$1.prototype.dlShiftTo = bnpDLShiftTo;
	BigInteger$1.prototype.drShiftTo = bnpDRShiftTo;
	BigInteger$1.prototype.lShiftTo = bnpLShiftTo;
	BigInteger$1.prototype.rShiftTo = bnpRShiftTo;
	BigInteger$1.prototype.subTo = bnpSubTo;
	BigInteger$1.prototype.multiplyTo = bnpMultiplyTo;
	BigInteger$1.prototype.squareTo = bnpSquareTo;
	BigInteger$1.prototype.divRemTo = bnpDivRemTo;
	BigInteger$1.prototype.invDigit = bnpInvDigit;
	BigInteger$1.prototype.isEven = bnpIsEven;
	BigInteger$1.prototype.exp = bnpExp;

	// public
	BigInteger$1.prototype.toString = bnToString;
	BigInteger$1.prototype.negate = bnNegate;
	BigInteger$1.prototype.abs = bnAbs;
	BigInteger$1.prototype.compareTo = bnCompareTo;
	BigInteger$1.prototype.bitLength = bnBitLength;
	BigInteger$1.prototype.mod = bnMod;
	BigInteger$1.prototype.modPowInt = bnModPowInt;

	// "constants"
	BigInteger$1.ZERO = nbv(0);
	BigInteger$1.ONE = nbv(1);

	/* ecdsa-modified-1.1.1.js (c) Stephan Thomas, Kenji Urushima | github.com/bitcoinjs/bitcoinjs-lib/blob/master/LICENSE
	 */
	/*
	 * ecdsa-modified.js - modified Bitcoin.ECDSA class
	 * 
	 * Copyright (c) 2013-2017 Stefan Thomas (github.com/justmoon)
	 *                         Kenji Urushima (kenji.urushima@gmail.com)
	 * LICENSE
	 *   https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/LICENSE
	 */

	/**
	 * @fileOverview
	 * @name ecdsa-modified-1.0.js
	 * @author Stefan Thomas (github.com/justmoon) and Kenji Urushima (kenji.urushima@gmail.com)
	 * @version jsrsasign 7.2.0 ecdsa-modified 1.1.1 (2017-May-12)
	 * @since jsrsasign 4.0
	 * @license <a href="https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/LICENSE">MIT License</a>
	 */

	if (typeof KJUR == "undefined" || !KJUR) KJUR = {};
	if (typeof KJUR.crypto == "undefined" || !KJUR.crypto) KJUR.crypto = {};

	/**
	 * class for EC key generation,  ECDSA signing and verifcation
	 * @name KJUR.crypto.ECDSA
	 * @class class for EC key generation,  ECDSA signing and verifcation
	 * @description
	 * <p>
	 * CAUTION: Most of the case, you don't need to use this class except
	 * for generating an EC key pair. Please use {@link KJUR.crypto.Signature} class instead.
	 * </p>
	 * <p>
	 * This class was originally developped by Stefan Thomas for Bitcoin JavaScript library.
	 * (See {@link https://github.com/bitcoinjs/bitcoinjs-lib/blob/master/src/ecdsa.js})
	 * Currently this class supports following named curves and their aliases.
	 * <ul>
	 * <li>secp256r1, NIST P-256, P-256, prime256v1 (*)</li>
	 * <li>secp256k1 (*)</li>
	 * <li>secp384r1, NIST P-384, P-384 (*)</li>
	 * </ul>
	 * </p>
	 */
	KJUR.crypto.ECDSA = function(params) {
	    var curveName = "secp256r1";	// curve name default

	    var rng = new SecureRandom();

	    this.type = "EC";
	    this.isPrivate = false;
	    this.isPublic = false;

	    //===========================
	    // PUBLIC METHODS
	    //===========================
	    this.getBigRandom = function (limit) {
		return new BigInteger(limit.bitLength(), rng)
		.mod(limit.subtract(BigInteger.ONE))
		.add(BigInteger.ONE)
		;
	    };

	    this.setNamedCurve = function(curveName) {
		this.ecparams = KJUR.crypto.ECParameterDB.getByName(curveName);
		this.prvKeyHex = null;
		this.pubKeyHex = null;
		this.curveName = curveName;
	    };

	    this.setPrivateKeyHex = function(prvKeyHex) {
	        this.isPrivate = true;
		this.prvKeyHex = prvKeyHex;
	    };

	    this.setPublicKeyHex = function(pubKeyHex) {
	        this.isPublic = true;
		this.pubKeyHex = pubKeyHex;
	    };

	    /**
	     * get X and Y hexadecimal string value of public key
	     * @name getPublicKeyXYHex
	     * @memberOf KJUR.crypto.ECDSA#
	     * @function
	     * @return {Array} associative array of x and y value of public key
	     * @since ecdsa-modified 1.0.5 jsrsasign 5.0.14
	     * @example
	     * ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1', 'pub': pubHex});
	     * ec.getPublicKeyXYHex() &rarr; { x: '01bacf...', y: 'c3bc22...' }
	     */
	    this.getPublicKeyXYHex = function() {
		var h = this.pubKeyHex;
		if (h.substr(0, 2) !== "04")
		    throw "this method supports uncompressed format(04) only";

		var charlen = this.ecparams.keylen / 4;
		if (h.length !== 2 + charlen * 2)
		    throw "malformed public key hex length";

		var result = {};
		result.x = h.substr(2, charlen);
		result.y = h.substr(2 + charlen);
		return result;
	    };

	    /**
	     * get NIST curve short name such as "P-256" or "P-384"
	     * @name getShortNISTPCurveName
	     * @memberOf KJUR.crypto.ECDSA#
	     * @function
	     * @return {String} short NIST P curve name such as "P-256" or "P-384" if it's NIST P curve otherwise null;
	     * @since ecdsa-modified 1.0.5 jsrsasign 5.0.14
	     * @example
	     * ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1', 'pub': pubHex});
	     * ec.getShortPCurveName() &rarr; "P-256";
	     */
	    this.getShortNISTPCurveName = function() {
		var s = this.curveName;
		if (s === "secp256r1" || s === "NIST P-256" ||
		    s === "P-256" || s === "prime256v1")
		    return "P-256";
		if (s === "secp384r1" || s === "NIST P-384" || s === "P-384")
		    return "P-384";
		return null;
	    };

	    /**
	     * generate a EC key pair
	     * @name generateKeyPairHex
	     * @memberOf KJUR.crypto.ECDSA#
	     * @function
	     * @return {Array} associative array of hexadecimal string of private and public key
	     * @since ecdsa-modified 1.0.1
	     * @example
	     * var ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
	     * var keypair = ec.generateKeyPairHex();
	     * var pubhex = keypair.ecpubhex; // hexadecimal string of EC public key
	     * var prvhex = keypair.ecprvhex; // hexadecimal string of EC private key (=d)
	     */
	    this.generateKeyPairHex = function() {
		var biN = this.ecparams['n'];
		var biPrv = this.getBigRandom(biN);
		var epPub = this.ecparams['G'].multiply(biPrv);
		var biX = epPub.getX().toBigInteger();
		var biY = epPub.getY().toBigInteger();

		var charlen = this.ecparams['keylen'] / 4;
		var hPrv = ("0000000000" + biPrv.toString(16)).slice(- charlen);
		var hX   = ("0000000000" + biX.toString(16)).slice(- charlen);
		var hY   = ("0000000000" + biY.toString(16)).slice(- charlen);
		var hPub = "04" + hX + hY;

		this.setPrivateKeyHex(hPrv);
		this.setPublicKeyHex(hPub);
		return {'ecprvhex': hPrv, 'ecpubhex': hPub};
	    };

	    this.signWithMessageHash = function(hashHex) {
		return this.signHex(hashHex, this.prvKeyHex);
	    };

	    /**
	     * signing to message hash
	     * @name signHex
	     * @memberOf KJUR.crypto.ECDSA#
	     * @function
	     * @param {String} hashHex hexadecimal string of hash value of signing message
	     * @param {String} privHex hexadecimal string of EC private key
	     * @return {String} hexadecimal string of ECDSA signature
	     * @since ecdsa-modified 1.0.1
	     * @example
	     * var ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
	     * var sigValue = ec.signHex(hash, prvKey);
	     */
	    this.signHex = function (hashHex, privHex) {
		var d = new BigInteger(privHex, 16);
		var n = this.ecparams['n'];
		var e = new BigInteger(hashHex, 16);

		do {
		    var k = this.getBigRandom(n);
		    var G = this.ecparams['G'];
		    var Q = G.multiply(k);
		    var r = Q.getX().toBigInteger().mod(n);
		} while (r.compareTo(BigInteger.ZERO) <= 0);

		var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);

		return KJUR.crypto.ECDSA.biRSSigToASN1Sig(r, s);
	    };

	    this.sign = function (hash, priv) {
		var d = priv;
		var n = this.ecparams['n'];
		var e = BigInteger.fromByteArrayUnsigned(hash);

		do {
		    var k = this.getBigRandom(n);
		    var G = this.ecparams['G'];
		    var Q = G.multiply(k);
		    var r = Q.getX().toBigInteger().mod(n);
		} while (r.compareTo(BigInteger.ZERO) <= 0);

		var s = k.modInverse(n).multiply(e.add(d.multiply(r))).mod(n);
		return this.serializeSig(r, s);
	    };

	    this.verifyWithMessageHash = function(hashHex, sigHex) {
		return this.verifyHex(hashHex, sigHex, this.pubKeyHex);
	    };

	    /**
	     * verifying signature with message hash and public key
	     * @name verifyHex
	     * @memberOf KJUR.crypto.ECDSA#
	     * @function
	     * @param {String} hashHex hexadecimal string of hash value of signing message
	     * @param {String} sigHex hexadecimal string of signature value
	     * @param {String} pubkeyHex hexadecimal string of public key
	     * @return {Boolean} true if the signature is valid, otherwise false
	     * @since ecdsa-modified 1.0.1
	     * @example
	     * var ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
	     * var result = ec.verifyHex(msgHashHex, sigHex, pubkeyHex);
	     */
	    this.verifyHex = function(hashHex, sigHex, pubkeyHex) {
		var r,s;

		var obj = KJUR.crypto.ECDSA.parseSigHex(sigHex);
		r = obj.r;
		s = obj.s;

		var Q;
		Q = ECPointFp.decodeFromHex(this.ecparams['curve'], pubkeyHex);
		var e = new BigInteger(hashHex, 16);

		return this.verifyRaw(e, r, s, Q);
	    };

	    this.verify = function (hash, sig, pubkey) {
		var r,s;
		if (Bitcoin.Util.isArray(sig)) {
		    var obj = this.parseSig(sig);
		    r = obj.r;
		    s = obj.s;
		} else if ("object" === typeof sig && sig.r && sig.s) {
		    r = sig.r;
		    s = sig.s;
		} else {
		    throw "Invalid value for signature";
		}

		var Q;
		if (pubkey instanceof ECPointFp) {
		    Q = pubkey;
		} else if (Bitcoin.Util.isArray(pubkey)) {
		    Q = ECPointFp.decodeFrom(this.ecparams['curve'], pubkey);
		} else {
		    throw "Invalid format for pubkey value, must be byte array or ECPointFp";
		}
		var e = BigInteger.fromByteArrayUnsigned(hash);

		return this.verifyRaw(e, r, s, Q);
	    };

	    this.verifyRaw = function (e, r, s, Q) {
		var n = this.ecparams['n'];
		var G = this.ecparams['G'];

		if (r.compareTo(BigInteger.ONE) < 0 ||
		    r.compareTo(n) >= 0)
		    return false;

		if (s.compareTo(BigInteger.ONE) < 0 ||
		    s.compareTo(n) >= 0)
		    return false;

		var c = s.modInverse(n);

		var u1 = e.multiply(c).mod(n);
		var u2 = r.multiply(c).mod(n);

		// TODO(!!!): For some reason Shamir's trick isn't working with
		// signed message verification!? Probably an implementation
		// error!
		//var point = implShamirsTrick(G, u1, Q, u2);
		var point = G.multiply(u1).add(Q.multiply(u2));

		var v = point.getX().toBigInteger().mod(n);

		return v.equals(r);
	    };

	    /**
	     * Serialize a signature into DER format.
	     *
	     * Takes two BigIntegers representing r and s and returns a byte array.
	     */
	    this.serializeSig = function (r, s) {
		var rBa = r.toByteArraySigned();
		var sBa = s.toByteArraySigned();

		var sequence = [];
		sequence.push(0x02); // INTEGER
		sequence.push(rBa.length);
		sequence = sequence.concat(rBa);

		sequence.push(0x02); // INTEGER
		sequence.push(sBa.length);
		sequence = sequence.concat(sBa);

		sequence.unshift(sequence.length);
		sequence.unshift(0x30); // SEQUENCE
		return sequence;
	    };

	    /**
	     * Parses a byte array containing a DER-encoded signature.
	     *
	     * This function will return an object of the form:
	     *
	     * {
	     *   r: BigInteger,
	     *   s: BigInteger
	     * }
	     */
	    this.parseSig = function (sig) {
		var cursor;
		if (sig[0] != 0x30)
		    throw new Error("Signature not a valid DERSequence");

		cursor = 2;
		if (sig[cursor] != 0x02)
		    throw new Error("First element in signature must be a DERInteger");	var rBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

		cursor += 2+sig[cursor+1];
		if (sig[cursor] != 0x02)
		    throw new Error("Second element in signature must be a DERInteger");
		var sBa = sig.slice(cursor+2, cursor+2+sig[cursor+1]);

		cursor += 2+sig[cursor+1];

		//if (cursor != sig.length)
		//  throw new Error("Extra bytes in signature");

		var r = BigInteger.fromByteArrayUnsigned(rBa);
		var s = BigInteger.fromByteArrayUnsigned(sBa);

		return {r: r, s: s};
	    };

	    this.parseSigCompact = function (sig) {
		if (sig.length !== 65) {
		    throw "Signature has the wrong length";
		}

		// Signature is prefixed with a type byte storing three bits of
		// information.
		var i = sig[0] - 27;
		if (i < 0 || i > 7) {
		    throw "Invalid signature type";
		}

		var n = this.ecparams['n'];
		var r = BigInteger.fromByteArrayUnsigned(sig.slice(1, 33)).mod(n);
		var s = BigInteger.fromByteArrayUnsigned(sig.slice(33, 65)).mod(n);

		return {r: r, s: s, i: i};
	    };

	    /**
	     * read an ASN.1 hexadecimal string of PKCS#1/5 plain ECC private key<br/>
	     * @name readPKCS5PrvKeyHex
	     * @memberOf KJUR.crypto.ECDSA#
	     * @function
	     * @param {String} h hexadecimal string of PKCS#1/5 ECC private key
	     * @since jsrsasign 7.1.0 ecdsa-modified 1.1.0
	     */
	    this.readPKCS5PrvKeyHex = function(h) {
		var _ASN1HEX = ASN1HEX;
		var _getName = KJUR.crypto.ECDSA.getName;
		var _getVbyList = _ASN1HEX.getVbyList;

		if (_ASN1HEX.isASN1HEX(h) === false)
		    throw "not ASN.1 hex string";

		var hCurve, hPrv, hPub;
		try {
		    hCurve = _getVbyList(h, 0, [2, 0], "06");
		    hPrv   = _getVbyList(h, 0, [1], "04");
		    try {
			hPub = _getVbyList(h, 0, [3, 0], "03").substr(2);
		    } catch(ex) {}	} catch(ex) {
		    throw "malformed PKCS#1/5 plain ECC private key";
		}

		this.curveName = _getName(hCurve);
		if (this.curveName === undefined) throw "unsupported curve name";

		this.setNamedCurve(this.curveName);
		this.setPublicKeyHex(hPub);
		this.setPrivateKeyHex(hPrv);
	        this.isPublic = false;
	    };

	    /**
	     * read an ASN.1 hexadecimal string of PKCS#8 plain ECC private key<br/>
	     * @name readPKCS8PrvKeyHex
	     * @memberOf KJUR.crypto.ECDSA#
	     * @function
	     * @param {String} h hexadecimal string of PKCS#8 ECC private key
	     * @since jsrsasign 7.1.0 ecdsa-modified 1.1.0
	     */
	    this.readPKCS8PrvKeyHex = function(h) {
		var _ASN1HEX = ASN1HEX;
		var _getName = KJUR.crypto.ECDSA.getName;
		var _getVbyList = _ASN1HEX.getVbyList;

		if (_ASN1HEX.isASN1HEX(h) === false)
		    throw "not ASN.1 hex string";

		var hECOID, hCurve, hPrv, hPub;
		try {
		    hECOID = _getVbyList(h, 0, [1, 0], "06");
		    hCurve = _getVbyList(h, 0, [1, 1], "06");
		    hPrv   = _getVbyList(h, 0, [2, 0, 1], "04");
		    try {
			hPub = _getVbyList(h, 0, [2, 0, 2, 0], "03").substr(2);
		    } catch(ex) {}	} catch(ex) {
		    throw "malformed PKCS#8 plain ECC private key";
		}

		this.curveName = _getName(hCurve);
		if (this.curveName === undefined) throw "unsupported curve name";

		this.setNamedCurve(this.curveName);
		this.setPublicKeyHex(hPub);
		this.setPrivateKeyHex(hPrv);
	        this.isPublic = false;
	    };

	    /**
	     * read an ASN.1 hexadecimal string of PKCS#8 ECC public key<br/>
	     * @name readPKCS8PubKeyHex
	     * @memberOf KJUR.crypto.ECDSA#
	     * @function
	     * @param {String} h hexadecimal string of PKCS#8 ECC public key
	     * @since jsrsasign 7.1.0 ecdsa-modified 1.1.0
	     */
	    this.readPKCS8PubKeyHex = function(h) {
		var _ASN1HEX = ASN1HEX;
		var _getName = KJUR.crypto.ECDSA.getName;
		var _getVbyList = _ASN1HEX.getVbyList;

		if (_ASN1HEX.isASN1HEX(h) === false)
		    throw "not ASN.1 hex string";

		var hECOID, hCurve, hPub;
		try {
		    hECOID = _getVbyList(h, 0, [0, 0], "06");
		    hCurve = _getVbyList(h, 0, [0, 1], "06");
		    hPub = _getVbyList(h, 0, [1], "03").substr(2);
		} catch(ex) {
		    throw "malformed PKCS#8 ECC public key";
		}

		this.curveName = _getName(hCurve);
		if (this.curveName === null) throw "unsupported curve name";

		this.setNamedCurve(this.curveName);
		this.setPublicKeyHex(hPub);
	    };

	    /**
	     * read an ASN.1 hexadecimal string of X.509 ECC public key certificate<br/>
	     * @name readCertPubKeyHex
	     * @memberOf KJUR.crypto.ECDSA#
	     * @function
	     * @param {String} h hexadecimal string of X.509 ECC public key certificate
	     * @param {Integer} nthPKI nth index of publicKeyInfo. (DEFAULT: 6 for X509v3)
	     * @since jsrsasign 7.1.0 ecdsa-modified 1.1.0
	     */
	    this.readCertPubKeyHex = function(h, nthPKI) {
		if (nthPKI !== 5) nthPKI = 6;
		var _ASN1HEX = ASN1HEX;
		var _getName = KJUR.crypto.ECDSA.getName;
		var _getVbyList = _ASN1HEX.getVbyList;

		if (_ASN1HEX.isASN1HEX(h) === false)
		    throw "not ASN.1 hex string";

		var hCurve, hPub;
		try {
		    hCurve = _getVbyList(h, 0, [0, nthPKI, 0, 1], "06");
		    hPub = _getVbyList(h, 0, [0, nthPKI, 1], "03").substr(2);
		} catch(ex) {
		    throw "malformed X.509 certificate ECC public key";
		}

		this.curveName = _getName(hCurve);
		if (this.curveName === null) throw "unsupported curve name";

		this.setNamedCurve(this.curveName);
		this.setPublicKeyHex(hPub);
	    };

	    /*
	     * Recover a public key from a signature.
	     *
	     * See SEC 1: Elliptic Curve Cryptography, section 4.1.6, "Public
	     * Key Recovery Operation".
	     *
	     * http://www.secg.org/download/aid-780/sec1-v2.pdf
	     */
	    /*
	    recoverPubKey: function (r, s, hash, i) {
		// The recovery parameter i has two bits.
		i = i & 3;

		// The less significant bit specifies whether the y coordinate
		// of the compressed point is even or not.
		var isYEven = i & 1;

		// The more significant bit specifies whether we should use the
		// first or second candidate key.
		var isSecondKey = i >> 1;

		var n = this.ecparams['n'];
		var G = this.ecparams['G'];
		var curve = this.ecparams['curve'];
		var p = curve.getQ();
		var a = curve.getA().toBigInteger();
		var b = curve.getB().toBigInteger();

		// We precalculate (p + 1) / 4 where p is if the field order
		if (!P_OVER_FOUR) {
		    P_OVER_FOUR = p.add(BigInteger.ONE).divide(BigInteger.valueOf(4));
		}

		// 1.1 Compute x
		var x = isSecondKey ? r.add(n) : r;

		// 1.3 Convert x to point
		var alpha = x.multiply(x).multiply(x).add(a.multiply(x)).add(b).mod(p);
		var beta = alpha.modPow(P_OVER_FOUR, p);

		var xorOdd = beta.isEven() ? (i % 2) : ((i+1) % 2);
		// If beta is even, but y isn't or vice versa, then convert it,
		// otherwise we're done and y == beta.
		var y = (beta.isEven() ? !isYEven : isYEven) ? beta : p.subtract(beta);

		// 1.4 Check that nR is at infinity
		var R = new ECPointFp(curve,
				      curve.fromBigInteger(x),
				      curve.fromBigInteger(y));
		R.validate();

		// 1.5 Compute e from M
		var e = BigInteger.fromByteArrayUnsigned(hash);
		var eNeg = BigInteger.ZERO.subtract(e).mod(n);

		// 1.6 Compute Q = r^-1 (sR - eG)
		var rInv = r.modInverse(n);
		var Q = implShamirsTrick(R, s, G, eNeg).multiply(rInv);

		Q.validate();
		if (!this.verifyRaw(e, r, s, Q)) {
		    throw "Pubkey recovery unsuccessful";
		}

		var pubKey = new Bitcoin.ECKey();
		pubKey.pub = Q;
		return pubKey;
	    },
	    */

	    /*
	     * Calculate pubkey extraction parameter.
	     *
	     * When extracting a pubkey from a signature, we have to
	     * distinguish four different cases. Rather than putting this
	     * burden on the verifier, Bitcoin includes a 2-bit value with the
	     * signature.
	     *
	     * This function simply tries all four cases and returns the value
	     * that resulted in a successful pubkey recovery.
	     */
	    /*
	    calcPubkeyRecoveryParam: function (address, r, s, hash) {
		for (var i = 0; i < 4; i++) {
		    try {
			var pubkey = Bitcoin.ECDSA.recoverPubKey(r, s, hash, i);
			if (pubkey.getBitcoinAddress().toString() == address) {
			    return i;
			}
		    } catch (e) {}
		}
		throw "Unable to find valid recovery factor";
	    }
	    */

	    if (params !== undefined) {
		if (params['curve'] !== undefined) {
		    this.curveName = params['curve'];
		}
	    }
	    if (this.curveName === undefined) this.curveName = curveName;
	    this.setNamedCurve(this.curveName);
	    if (params !== undefined) {
		if (params.prv !== undefined) this.setPrivateKeyHex(params.prv);
		if (params.pub !== undefined) this.setPublicKeyHex(params.pub);
	    }
	};

	/**
	 * parse ASN.1 DER encoded ECDSA signature
	 * @name parseSigHex
	 * @memberOf KJUR.crypto.ECDSA
	 * @function
	 * @static
	 * @param {String} sigHex hexadecimal string of ECDSA signature value
	 * @return {Array} associative array of signature field r and s of BigInteger
	 * @since ecdsa-modified 1.0.1
	 * @example
	 * var ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
	 * var sig = ec.parseSigHex('30...');
	 * var biR = sig.r; // BigInteger object for 'r' field of signature.
	 * var biS = sig.s; // BigInteger object for 's' field of signature.
	 */
	KJUR.crypto.ECDSA.parseSigHex = function(sigHex) {
	    var p = KJUR.crypto.ECDSA.parseSigHexInHexRS(sigHex);
	    var biR = new BigInteger(p.r, 16);
	    var biS = new BigInteger(p.s, 16);
	    
	    return {'r': biR, 's': biS};
	};

	/**
	 * parse ASN.1 DER encoded ECDSA signature
	 * @name parseSigHexInHexRS
	 * @memberOf KJUR.crypto.ECDSA
	 * @function
	 * @static
	 * @param {String} sigHex hexadecimal string of ECDSA signature value
	 * @return {Array} associative array of signature field r and s in hexadecimal
	 * @since ecdsa-modified 1.0.3
	 * @example
	 * var ec = new KJUR.crypto.ECDSA({'curve': 'secp256r1'});
	 * var sig = ec.parseSigHexInHexRS('30...');
	 * var hR = sig.r; // hexadecimal string for 'r' field of signature.
	 * var hS = sig.s; // hexadecimal string for 's' field of signature.
	 */
	KJUR.crypto.ECDSA.parseSigHexInHexRS = function(sigHex) {
	    var _ASN1HEX = ASN1HEX;
	    var _getChildIdx = _ASN1HEX.getChildIdx;
	    var _getV = _ASN1HEX.getV;

	    // 1. ASN.1 Sequence Check
	    if (sigHex.substr(0, 2) != "30")
		throw "signature is not a ASN.1 sequence";

	    // 2. Items of ASN.1 Sequence Check
	    var a = _getChildIdx(sigHex, 0);
	    if (a.length != 2)
		throw "number of signature ASN.1 sequence elements seem wrong";
	    
	    // 3. Integer check
	    var iTLV1 = a[0];
	    var iTLV2 = a[1];
	    if (sigHex.substr(iTLV1, 2) != "02")
		throw "1st item of sequene of signature is not ASN.1 integer";
	    if (sigHex.substr(iTLV2, 2) != "02")
		throw "2nd item of sequene of signature is not ASN.1 integer";

	    // 4. getting value
	    var hR = _getV(sigHex, iTLV1);
	    var hS = _getV(sigHex, iTLV2);
	    
	    return {'r': hR, 's': hS};
	};

	/**
	 * convert hexadecimal ASN.1 encoded signature to concatinated signature
	 * @name asn1SigToConcatSig
	 * @memberOf KJUR.crypto.ECDSA
	 * @function
	 * @static
	 * @param {String} asn1Hex hexadecimal string of ASN.1 encoded ECDSA signature value
	 * @return {String} r-s concatinated format of ECDSA signature value
	 * @since ecdsa-modified 1.0.3
	 */
	KJUR.crypto.ECDSA.asn1SigToConcatSig = function(asn1Sig) {
	    var pSig = KJUR.crypto.ECDSA.parseSigHexInHexRS(asn1Sig);
	    var hR = pSig.r;
	    var hS = pSig.s;

	    // R and S length is assumed multiple of 128bit(32chars in hex).
	    // If leading is "00" and modulo of length is 2(chars) then
	    // leading "00" is for two's complement and will be removed.
	    if (hR.substr(0, 2) == "00" && (hR.length % 32) == 2)
		hR = hR.substr(2);

	    if (hS.substr(0, 2) == "00" && (hS.length % 32) == 2)
		hS = hS.substr(2);

	    // R and S length is assumed multiple of 128bit(32chars in hex).
	    // If missing two chars then it will be padded by "00".
	    if ((hR.length % 32) == 30) hR = "00" + hR;
	    if ((hS.length % 32) == 30) hS = "00" + hS;

	    // If R and S length is not still multiple of 128bit(32 chars),
	    // then error
	    if (hR.length % 32 != 0)
		throw "unknown ECDSA sig r length error";
	    if (hS.length % 32 != 0)
		throw "unknown ECDSA sig s length error";

	    return hR + hS;
	};

	/**
	 * convert hexadecimal concatinated signature to ASN.1 encoded signature
	 * @name concatSigToASN1Sig
	 * @memberOf KJUR.crypto.ECDSA
	 * @function
	 * @static
	 * @param {String} concatSig r-s concatinated format of ECDSA signature value
	 * @return {String} hexadecimal string of ASN.1 encoded ECDSA signature value
	 * @since ecdsa-modified 1.0.3
	 */
	KJUR.crypto.ECDSA.concatSigToASN1Sig = function(concatSig) {
	    if ((((concatSig.length / 2) * 8) % (16 * 8)) != 0)
		throw "unknown ECDSA concatinated r-s sig  length error";

	    var hR = concatSig.substr(0, concatSig.length / 2);
	    var hS = concatSig.substr(concatSig.length / 2);
	    return KJUR.crypto.ECDSA.hexRSSigToASN1Sig(hR, hS);
	};

	/**
	 * convert hexadecimal R and S value of signature to ASN.1 encoded signature
	 * @name hexRSSigToASN1Sig
	 * @memberOf KJUR.crypto.ECDSA
	 * @function
	 * @static
	 * @param {String} hR hexadecimal string of R field of ECDSA signature value
	 * @param {String} hS hexadecimal string of S field of ECDSA signature value
	 * @return {String} hexadecimal string of ASN.1 encoded ECDSA signature value
	 * @since ecdsa-modified 1.0.3
	 */
	KJUR.crypto.ECDSA.hexRSSigToASN1Sig = function(hR, hS) {
	    var biR = new BigInteger(hR, 16);
	    var biS = new BigInteger(hS, 16);
	    return KJUR.crypto.ECDSA.biRSSigToASN1Sig(biR, biS);
	};

	/**
	 * convert R and S BigInteger object of signature to ASN.1 encoded signature
	 * @name biRSSigToASN1Sig
	 * @memberOf KJUR.crypto.ECDSA
	 * @function
	 * @static
	 * @param {BigInteger} biR BigInteger object of R field of ECDSA signature value
	 * @param {BigInteger} biS BIgInteger object of S field of ECDSA signature value
	 * @return {String} hexadecimal string of ASN.1 encoded ECDSA signature value
	 * @since ecdsa-modified 1.0.3
	 */
	KJUR.crypto.ECDSA.biRSSigToASN1Sig = function(biR, biS) {
	    var _KJUR_asn1 = KJUR.asn1;
	    var derR = new _KJUR_asn1.DERInteger({'bigint': biR});
	    var derS = new _KJUR_asn1.DERInteger({'bigint': biS});
	    var derSeq = new _KJUR_asn1.DERSequence({'array': [derR, derS]});
	    return derSeq.getEncodedHex();
	};

	/**
	 * static method to get normalized EC curve name from curve name or hexadecimal OID value
	 * @name getName
	 * @memberOf KJUR.crypto.ECDSA
	 * @function
	 * @static
	 * @param {String} s curve name (ex. P-256) or hexadecimal OID value (ex. 2a86...)
	 * @return {String} normalized EC curve name (ex. secp256r1) 
	 * @since jsrsasign 7.1.0 ecdsa-modified 1.1.0 
	 * @description
	 * This static method returns normalized EC curve name 
	 * which is supported in jsrsasign
	 * from curve name or hexadecimal OID value.
	 * When curve is not supported in jsrsasign, this method returns null.
	 * Normalized name will be "secp*" in jsrsasign.
	 * @example
	 * KJUR.crypto.ECDSA.getName("2b8104000a") &rarr; "secp256k1"
	 * KJUR.crypto.ECDSA.getName("NIST P-256") &rarr; "secp256r1"
	 * KJUR.crypto.ECDSA.getName("P-521") &rarr; undefined // not supported
	 */
	KJUR.crypto.ECDSA.getName = function(s) {
	    if (s === "2a8648ce3d030107") return "secp256r1"; // 1.2.840.10045.3.1.7
	    if (s === "2b8104000a") return "secp256k1"; // 1.3.132.0.10
	    if (s === "2b81040022") return "secp384r1"; // 1.3.132.0.34
	    if ("|secp256r1|NIST P-256|P-256|prime256v1|".indexOf(s) !== -1) return "secp256r1";
	    if ("|secp256k1|".indexOf(s) !== -1) return "secp256k1";
	    if ("|secp384r1|NIST P-384|P-384|".indexOf(s) !== -1) return "secp384r1";
	    return null;
	};

	const BigInteger$2 = window.BigInteger;
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
	        r: new BigInteger$2(signHex.substr(0, ecdsaKeyLen), 16),
	        s: new BigInteger$2(signHex.substr(ecdsaKeyLen), 16)
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
	    return new BigInteger$2(trimHexPrefix(s), 16);
	}

	function normInt(b) {
	    return new BigInteger$2(b, 16).mod(ecdsa.ecparams.n).add(BigInteger$2.ONE).toString(16);
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

	const crypto$1 = {
	    hash,
	    xhash,
	    privateKeyBySecret,
	    publicKeyByPrivate,
	    addressByPublic
	};

	return crypto$1;

}());
