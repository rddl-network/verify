from fastapi.testclient import TestClient

from rddl_verify.main import app

client = TestClient(app)

pub_key = "03c150061989643d77162902b725409087959f15914649d4f06b6cc3f8c87bb238"
sig = "80757d800947b659640c672b9c60629caa2b634d561168043644ce2b07b7366827d7905330c27e7dcdaf31fc511f31e00856f582da977b9564e2c3bb746adb23"
hash = "7d381f4a480314a4d6947d497fbd9bfdfe8258876e9d4f57b6eefe99f7043783"
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
