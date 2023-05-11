from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from rddl_verify.routers import (
    hash_data,
    validate_content,
)

app = FastAPI()

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {"health": "ok"}


app.include_router(validate_content.router)
app.include_router(hash_data.router)
