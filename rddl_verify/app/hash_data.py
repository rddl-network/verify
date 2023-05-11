import hashlib
import json
from typing import List


def hash_data(data: List[dict]) -> str:
    h = hashlib.sha256()
    data_str = json.dumps(data)
    h.update(data_str.encode("utf-8"))
    return h.hexdigest()
