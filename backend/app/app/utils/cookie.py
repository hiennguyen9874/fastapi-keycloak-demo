import json
from typing import Dict, Any


__all__ = ["dict_encode_value", "decode"]


def decode(cookie: str) -> str:
    cookie = cookie.encode().decode("latin-1")
    cookie = cookie.replace(str(True), json.dumps(True))
    cookie = cookie.replace(str(False), json.dumps(False))
    cookie = cookie.replace(str(None), json.dumps(None))
    cookie = cookie.replace("'", '"')
    return cookie


def dict_encode_value(dict: Dict[str, Any]) -> Dict[str, Any]:
    new_dict = {}
    for key, value in dict.items():
        if type(value) == type({}):
            value = dict_encode_value(value)
        elif type(value) in [bool, None]:
            value = json.dumps(value)
        new_dict[key] = value
    return new_dict
