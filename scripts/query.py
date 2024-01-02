# -*- coding: utf-8 -*-

import sys
import os
import uuid
import hashlib
import time
import requests
import json


APP_KEY = os.getenv("APP_KEY")
APP_SECRET = os.getenv("APP_SECRET")

# TODO if APP_KEY or APP_SECRET not set


def encrypt(signStr):
    hash_algorithm = hashlib.sha256()
    hash_algorithm.update(signStr.encode("utf-8"))
    return hash_algorithm.hexdigest()


def truncate(q):
    if q is None:
        return None
    size = len(q)
    return q if size <= 20 else q[0:10] + str(size) + q[size - 10 : size]


def do_request(data):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    return requests.post("https://openapi.youdao.com/api", data=data, headers=headers)


def connect(q):
    if all(ord(c) < 256 for c in q):
        _from = "en"
        _to = "zh_CHS"
    else:
        _from = "zh_CHS"
        _to = "en"

    data = {}
    data["from"] = _from
    data["to"] = _to
    data["signType"] = "v3"
    curtime = str(int(time.time()))
    data["curtime"] = curtime
    salt = str(uuid.uuid1())
    signStr = APP_KEY + truncate(q) + salt + curtime + APP_SECRET
    sign = encrypt(signStr)
    data["appKey"] = APP_KEY
    data["q"] = q
    data["salt"] = salt
    data["sign"] = sign

    response = do_request(data)
    content = response.json()
    results = []
    q = content["query"]
    if content["errorCode"] == "0":
        if "translation" in content:
            for v in content["translation"]:
                results.append(
                    {
                        "title": v,
                        "subtitle": q,
                        "icon": {"path": "assets/translate.png"},
                    }
                )
        if "basic" in content:
            for v in content["basic"]["explains"]:
                results.append(
                    {
                        "title": v,
                        "subtitle": q,
                        "icon": {"path": "assets/translate.png"},
                    }
                )
        if "web" in content:
            for obj in content["web"]:
                results.append(
                    {
                        "title": ",".join(obj["value"]),
                        "subtitle": obj["key"],
                        "icon": {"path": "assets/translate.png"},
                    }
                )
    sys.stdout.write(json.dumps({"items": results}, ensure_ascii=False))


query = sys.argv[1]
connect(query)
