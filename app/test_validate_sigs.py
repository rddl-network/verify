import json
import pytest
import hashlib

import wallycore as wally
import verify_signature
#from ..models import validation_result
import hashlib

def get_key_pair():
    priv_key_wif = 'cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N'
    priv_key = wally.wif_to_bytes(priv_key_wif, wally.WIF_PREFIX, wally.WALLY_WIF_FLAG_COMPRESSED)
    pub_key = wally.ec_public_key_from_private_key(priv_key)
    return priv_key, pub_key

def sign( priv_key, hash:bytes):
    return wally.ec_sig_from_bytes( priv_key,  hash, wally.EC_FLAG_ECDSA)


def test_verify_hash():

    hash = hashlib.sha3_256()
    hash.update(b'testmyhashlib')

    
    priv, pub = get_key_pair()
    sig = sign(priv, hash.digest())
    result = verify_signature.validate_signature_data_hash( pub, sig, hash.digest())
    
    assert result.json_obj == {}
    assert result.str == ""
    assert result.data_digest == hash.digest()
    assert result.is_valid == True
