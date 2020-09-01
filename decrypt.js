const { PublicKey, PrivateKey, Aes } = require('bitsharesjs');
const fs = require('fs');
const walletJSON = JSON.parse(fs.readFileSync('./PLAY-WALLET-JSON-FILE'));
const PREFIX = 'PLS';
const PASSWORD = 'PASSWORD';

const _parseWalletJson = function (json_contents) {
  let password_checksum;
  let encrypted_brainkey;
  let address_to_enckeys = {};
  let account_addresses = {};

  let savePubkeyAccount = function (pubkey, account_name) {
    //replace BTS with GPH
    pubkey = PREFIX + pubkey.substring(3);
    let address = PublicKey.fromPublicKeyString(
      pubkey,
      PREFIX
    ).toAddressString();

    let addresses = account_addresses[account_name] || [];
    address = PREFIX + address.substring(3);
    //DEBUG console.log("... address",address,account_name)
    addresses.push(address);
    account_addresses[account_name] = addresses;
  };

  try {
    if (!Array.isArray(json_contents)) {
      //DEBUG console.log('... json_contents',json_contents)
      throw new Error('Invalid wallet format');
    }
    for (let element of json_contents) {
      if (
        'key_record_type' == element.type &&
        element.data.account_address &&
        element.data.encrypted_private_key
      ) {
        let address = element.data.account_address;
        let enckeys = address_to_enckeys[address] || [];
        enckeys.push(element.data.encrypted_private_key);
        //DEBUG console.log("... address",address,enckeys)
        address_to_enckeys[address] = enckeys;
        continue;
      }

      if ('account_record_type' == element.type) {
        let account_name = element.data.name;
        savePubkeyAccount(element.data.owner_key, account_name);
        for (let history of element.data.active_key_history) {
          savePubkeyAccount(history[1], account_name);
        }
        continue;
      }

      if (
        'property_record_type' == element.type &&
        'encrypted_brainkey' == element.data.key
      ) {
        encrypted_brainkey = element.data.value;
        continue;
      }

      if ('master_key_record_type' == element.type) {
        if (!element.data)
          throw file.name + ' invalid master_key_record record';

        if (!element.data.checksum)
          throw file.name + ' is missing master_key_record checksum';

        password_checksum = element.data.checksum;
      }
    }
    // if (!encrypted_brainkey)
    //     throw "Please use a BTS 1.0 wallet_export_keys file instead";

    if (!password_checksum) throw file.name + ' is missing password_checksum';

    // if (!enckeys.length)
    //     throw file.name + " does not contain any private keys";
  } catch (e) {
    throw e.message || e;
  }

  let account_keys = [];
  for (let account_name in account_addresses) {
    let encrypted_private_keys = [];
    for (let address of account_addresses[account_name]) {
      let enckeys = address_to_enckeys[address];
      if (!enckeys) continue;
      for (let enckey of enckeys) encrypted_private_keys.push(enckey);
    }
    account_keys.push({
      account_name,
      encrypted_private_keys,
    });
  }
  // We could prompt for this brain key instead on first use.  The user
  // may already have a brainkey at this point so with a single brainkey
  // wallet we can't use it now.
  return {
    password_checksum,
    account_keys,
    //encrypted_brainkey
  };
};

const _decryptPrivateKeys = function (state, password) {
  let password_aes = Aes.fromSeed(password);
  for (let account of state.account_keys) {
    if (!account.encrypted_private_keys) {
      let error = `Account ${account.account_name} missing encrypted_private_keys`;
      console.error(error);
      continue;
    }
    let account_name = account.account_name.trim();
    let same_prefix_regex = new RegExp('^' + PREFIX);
    for (let i = 0; i < account.encrypted_private_keys.length; i++) {
      let encrypted_private = account.encrypted_private_keys[i];
      let public_key_string = account.public_keys
        ? account.public_keys[i]
        : null; // performance gain

      try {
        let private_plainhex = password_aes.decryptHex(encrypted_private);
        console.log('>>>>PrivateKey(Hex):\t', private_plainhex)
        let private_key = PrivateKey.fromHex(private_plainhex);
        console.log('>>>>PrivateKey(Base58):',private_key.toWif())
      } catch (e) {
        console.log(e, e.stack);
      }
    }
  }
};

const parsedResult = _parseWalletJson(walletJSON);

console.log(JSON.stringify(parsedResult, null, '  '));

_decryptPrivateKeys(parsedResult, PASSWORD);