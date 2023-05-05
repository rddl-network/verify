from fastapi import APIRouter
from models import verify_signature

router = APIRouter(
    prefix="/validate_tx",
    tags=["Validate Transaction"],
    responses={404: {"detail": "Not found"}},
)


@router.post("/validate/json")
async def validate_signature(pub_key: bytearray, signature: bytes, json_obj: dict):
    return verify_signature.validate_signature_json_data(pub_key, signature, json_obj)


@router.post("/validate/string")
async def validate_signature(pub_key: bytearray, signature: bytes, data_string: str):
    return verify_signature.validate_signature_data_string(pub_key, signature, data_string)


@router.post("/validate/hash")
async def validate_signature(pub_key: bytearray, signature: bytes, data_hash: bytearray):
    return verify_signature.validate_signature_data_hash(pub_key, signature, data_hash)
