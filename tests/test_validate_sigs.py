import json
import pytest
import hashlib

import wallycore as wally
from rddl_verify.app import verify_signature
import hashlib

WIF_PREFIX = 0xEF


def get_key_pair():
    priv_key_wif = "cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N"
    priv_key = wally.wif_to_bytes(priv_key_wif, WIF_PREFIX, wally.WALLY_WIF_FLAG_COMPRESSED)
    pub_key = wally.ec_public_key_from_private_key(priv_key)
    return priv_key, pub_key


def sign(priv_key, hash: bytes):
    return wally.ec_sig_from_bytes(priv_key, hash, wally.EC_FLAG_ECDSA)


def test_verify_hash():
    json_dict = {"a": "dear Test", "b": "welcome"}
    json_str = json.dumps(json_dict)
    bytestring = bytes(json_str, "utf-8")
    hash_local = hashlib.sha3_256()
    hash_local.update(bytestring)

    priv, pub = get_key_pair()
    sig = sign(priv, hash_local.digest())

    json_obt_result = verify_signature.validate_signature_json_data(pub, sig, json_dict)
    string_result = verify_signature.validate_signature_data_string(pub, sig, json_str)
    hash_result = verify_signature.validate_signature_data_hash(pub, sig, hash_local.digest())

    assert json_obt_result.json_obj == json_dict
    assert json_obt_result.data_str == json_str
    assert json_obt_result.data_digest == hash_local.digest().hex()
    assert json_obt_result.is_valid == True

    assert string_result.json_obj == {}
    assert string_result.data_str == json_str
    assert string_result.data_digest == hash_local.digest().hex()
    assert string_result.is_valid == True

    assert hash_result.json_obj == {}
    assert hash_result.data_str == ""
    assert hash_result.data_digest == hash_local.digest().hex()
    assert hash_result.is_valid == True
