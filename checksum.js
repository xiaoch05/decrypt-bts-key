const {PrivateKey,hash} = require('bitsharesjs');
let password = "PASSWORD";
let checksum = "CHECKSUM";
let newchecksum = hash.sha512(hash.sha512(password)).toString('hex');
console.log('checksum:\t', checksum)
console.log('new checksum:\t', newchecksum)
console.log('validation:\t',newchecksum == checksum);
