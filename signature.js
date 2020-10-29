const { Signature, PublicKey, PrivateKey, key, Aes } = require('bitsharesjs');
const Buffer = require("safe-buffer").Buffer;
const assert = require('assert');

let seed = "THIS IS A TERRIBLE BRAINKEY SEED WORD SEQUENCE";
let prikey = PrivateKey.fromSeed( key.normalize_brainKey(seed) );
let pubkey = prikey.toPublicKey();

console.log("\nPrivate key:", prikey.toWif());
console.log("Public key :", pubkey.toString(), "\n");

let buf = Buffer.from("hello world!");
let sig = Signature.sign(buf, prikey);
let sighex = sig.toHex();
console.log("signature is ", sighex);

let signature = Signature.fromHex(sighex);
let verify = signature.verifyBuffer(buf, pubkey);
console.log("verify ", verify);
assert(verify, "verify signature failed");

let invalidPubkey = PublicKey.fromStringOrThrow("GPH7vbxtK1WaZqXsiCHPcjVFBewVj8HFRd5Z5XZDpN6Pvb2dZcMqK");
verify = signature.verifyBuffer(buf, invalidPubkey);
console.log("verify ", verify);
assert(!verify, "verify invalid signature failed");
