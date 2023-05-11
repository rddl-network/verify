import codecs
from fastapi import APIRouter, HTTPException
from rddl_verify.app import verify_signature
from rddl_verify.models.validation_result import ValidationResult

router = APIRouter(
    prefix="/validate",
    tags=["Validate Data"],
    responses={404: {"detail": "Not found"}},
)


def convert_key_sig(pub_key: str, signature: bytes):
    try:
        pub_key_bytes = codecs.decode(pub_key, "hex_codec")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=f"pub key: Invalid input parameter {e}")
    try:
        signature_bytes = codecs.decode(signature, "hex_codec")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=f"signature: Invalid input parameter {e}")
    return pub_key_bytes, signature_bytes


@router.post("/json", response_model=ValidationResult)
async def validate_json_object(pub_key: str, signature: str, data: dict):
    pub_key_bytes, signature_bytes = convert_key_sig(pub_key, signature)

    return verify_signature.validate_signature_json_data(pub_key_bytes, signature_bytes, data)


@router.post("/string", response_model=ValidationResult)
async def validate_data_string(pub_key: str, signature: str, data: str):
    pub_key_bytes, signature_bytes = convert_key_sig(pub_key, signature)

    return verify_signature.validate_signature_data_string(pub_key_bytes, signature_bytes, data)


@router.post("/hash", response_model=ValidationResult)
async def validate_data_hash(pub_key: str, signature: str, data: str):
    pub_key_bytes, signature_bytes = convert_key_sig(pub_key, signature)
    try:
        data_hash_bytes = codecs.decode(data, "hex_codec")
    except ValueError as e:
        raise HTTPException(status_code=404, detail=f"data: Invalid input parameter {e}")

    result = verify_signature.validate_signature_data_hash(pub_key_bytes, signature_bytes, data_hash_bytes)
    return result
