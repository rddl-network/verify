from fastapi.testclient import TestClient

from rddl_verify.main import app

client = TestClient(app)

pub_key = "03c150061989643d77162902b725409087959f15914649d4f06b6cc3f8c87bb238"
sig = "68fba9c12a74bbd3399b0efe9c924b884a2e037d827b147ec9ddd9c26217163a1776e73ffbf0b4655ac70ca565310d307f86a0c9c71e0c8926b47fdfafc8a7fc"
hash = "2fc3dbae8a4db255781b38340fd1e372ac0cb6d3bd4d9eeba417227d1d5f7b38"
obj_str = '{"a": "dear Test", "b": "welcome"}'
json_dict = {"a": "dear Test", "b": "welcome"}


def test_hash():
    response = client.get(f"validate/hash?pub_key={pub_key}&signature={sig}&data={hash}")
    assert response.status_code == 200
    assert response.json()["json_obj"] == {}
    assert response.json()["data_digest"] == hash
    assert response.json()["data_str"] == ""
    assert response.json()["is_valid"] == True


def test_str():
    response = client.get(f"validate/string?pub_key={pub_key}&signature={sig}&data={obj_str}")
    assert response.status_code == 200
    assert response.json()["json_obj"] == {}
    assert response.json()["data_digest"] == hash
    assert response.json()["data_str"] == obj_str
    assert response.json()["is_valid"] == True


def test_json():
    response = client.post(f"validate/json?pub_key={pub_key}&signature={sig}", json=json_dict)
    assert response.status_code == 200
    assert response.json()["json_obj"] == json_dict
    assert response.json()["data_digest"] == hash
    assert response.json()["data_str"] == obj_str
    assert response.json()["is_valid"] == True
