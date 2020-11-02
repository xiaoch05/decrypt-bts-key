const { Signature, PublicKey, PrivateKey, key, Aes } = require('bitsharesjs');
var fs=require('fs');
const Buffer = require("safe-buffer").Buffer;
const assert = require('assert');

const pls = fs.readFileSync('./PLS.txt');
let signatures = pls.toString().split("\n");

const testBuffer = Buffer.from("DACPLAY: Verification Test");

const verifySignature = function (content, pubkey, signatureHex) {
	console.log(`PublicKey:${pubkey}`);
	console.log(`signature:${signatureHex}`);
	let publicKey = PublicKey.fromPublicKeyString(pubkey, "PLS");
	let signature = Signature.fromHex(signatureHex);
	let verify = signature.verifyBuffer(content, publicKey);
	assert(verify, "verify signature failed");
	console.log("verify signature successed");
}

signatures.forEach(function(line){
    let signature = line.split(" ");
	if (signature.length == 3) {
		verifySignature(testBuffer, signature[0], signature[1]);
		console.log(signature);
	}
});
