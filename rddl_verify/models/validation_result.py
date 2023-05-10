from pydantic import BaseModel


class ValidationResult(BaseModel):
    json_obj: dict
    data_str: str
    data_digest: str
    is_valid: bool
