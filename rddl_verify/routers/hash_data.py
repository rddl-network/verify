import json

from fastapi import APIRouter, UploadFile, File
from typing import List

from rddl_verify.app.hash_data import hash_data

router = APIRouter(
    prefix="/hash_sha256",
    tags=["Hash SHA256"],
    responses={404: {"detail": "Not found"}},
)


@router.get("/data")
async def hash_data_endpoint(data: List[dict]):
    return {"hash": hash_data(data)}


@router.get("/file")
async def hash_file(file: UploadFile = File(...)):
    contents = await file.read()
    data = json.loads(contents)
    return {"hash": hash_data(data)}
