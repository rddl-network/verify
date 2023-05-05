import wallycore as wally
import hashlib
import json
from ..models.validation_result import ValidationResult


async def validate_signature_json_data(pub_key: bytearray, signature: bytearray, json_obj: dict) -> ValidationResult:
    json_obj_str = json.dumps(json_obj)
    result = validate_signature_data_string(pub_key, signature, json_obj_str)
    result.json_obj = json_obj
    return result


async def validate_signature_data_string(
    pub_key: bytearray, signature: bytearray, data_string: str
) -> ValidationResult:
    hash = hashlib.sha3_256()
    hash.update(data_string)
    result = validate_signature_data_hash(pub_key, signature, hash.digest())
    result.data_str = data_string
    return result


async def validate_signature_data_hash(
    pub_key: bytearray, signature: bytearray, data_digest: bytes
) -> ValidationResult:
    result = ValidationResult
    result.data_digest = data_digest
    try:
        wally.ec_sig_verify(pub_key, data_digest, wally.FLAG_ECDSA, signature)
    except ValueError:
        result.is_valid = False
    return result
