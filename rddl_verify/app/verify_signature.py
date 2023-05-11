import wallycore as wally
import hashlib
import json
from rddl_verify.models.validation_result import ValidationResult


def validate_signature_json_data(pub_key: bytearray, signature: bytearray, json_obj: dict) -> ValidationResult:
    json_obj_str = json.dumps(json_obj)
    result = validate_signature_data_string(pub_key, signature, json_obj_str)
    result.json_obj = json_obj
    return result


def validate_signature_data_string(pub_key: bytearray, signature: bytearray, data_string: str) -> ValidationResult:
    byte_string = bytes(data_string, "utf-8")
    hash_local = hashlib.sha256()
    hash_local.update(byte_string)
    result = validate_signature_data_hash(pub_key, signature, hash_local.digest())
    result.data_str = data_string
    return result


def validate_signature_data_hash(pub_key: bytearray, signature: bytearray, data_digest: bytes) -> ValidationResult:
    result = ValidationResult(json_obj={}, data_str="", data_digest=data_digest.hex(), is_valid=True)
    try:
        wally.ec_sig_verify(pub_key, data_digest, wally.EC_FLAG_ECDSA, signature)
    except ValueError:
        result.is_valid = False
    return result
