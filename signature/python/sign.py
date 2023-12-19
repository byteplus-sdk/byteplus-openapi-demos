# coding:utf-8
"""
Copyright 2023 Byteplus Pte. Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

import datetime
import hashlib
import hmac
from urllib.parse import quote

import requests

# The following parameters vary based on the service and are usually consistent within a service.
Service = "iam"
Version = "2018-01-01"
Region = "ap-singapore-1"
Host = "open.byteplusapi.com"
ContentType = "application/x-www-form-urlencoded"

# Request credential, obtained from Identity and Access Management (IAM) or Security Token Service (STS)
AK = "AKExample***********"
SK = "QwERrtyasdf*********"
# When a temporary credential is used, SessionToken is required in the request header and needs to be calculated into the signed header. Add the X-Security-Token header to the header.
# SessionToken = ""


def norm_query(params):
    query = ""
    for key in sorted(params.keys()):
        if type(params[key]) == list:
            for k in params[key]:
                query = (
                        query + quote(key, safe="-_.~") + "=" + quote(k, safe="-_.~") + "&"
                )
        else:
            query = (query + quote(key, safe="-_.~") + "=" + quote(params[key], safe="-_.~") + "&")
    query = query[:-1]
    return query.replace("+", "%20")


# Step 1: Prepare an auxiliary function.
# SHA-256 asymmetric encryption
def hmac_sha256(key: bytes, content: str):
    return hmac.new(key, content.encode("utf-8"), hashlib.sha256).digest()


# SHA-256 hash algorithm
def hash_sha256(content: str):
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


# Step 2: Sign the request function.
def request(method, date, query, header, ak, sk, action, body):
    # Step 3: Create an identity credential. 
    # The values of the Service and Region fields are fixed and the values of the ak and sk fields indicate an access key ID and a secret access key, respectively. 
    # Signature struct initialization is also required. Some attributes required for signature calculation also need to be processed here.
    # Initialize the identity credential struct.
    credential = {
        "access_key_id": ak,
        "secret_access_key": sk,
        "service": Service,
        "region": Region,
    }
    # Initialize the signature struct.
    request_param = {
        "body": body,
        "host": Host,
        "path": "/",
        "method": method,
        "content_type": ContentType,
        "date": date,
        "query": {"Action": action, "Version": Version, **query},
    }
    if body is None:
        request_param["body"] = ""
    # Step 4: Prepare a signResult variable for receiving the signature calculation result and set the required parameters.
    # Initialize the signature result struct.
    x_date = request_param["date"].strftime("%Y%m%dT%H%M%SZ")
    short_x_date = x_date[:8]
    x_content_sha256 = hash_sha256(request_param["body"])
    sign_result = {
        "Host": request_param["host"],
        "X-Content-Sha256": x_content_sha256,
        "X-Date": x_date,
        "Content-Type": request_param["content_type"],
    }
    # Step 5: Calculate a signature.
    signed_headers_str = ";".join(
        ["content-type", "host", "x-content-sha256", "x-date"]
    )
    # signed_headers_str = signed_headers_str + ";x-security-token"
    canonical_request_str = "\n".join(
        [request_param["method"].upper(),
         request_param["path"],
         norm_query(request_param["query"]),
         "\n".join(
             [
                 "content-type:" + request_param["content_type"],
                 "host:" + request_param["host"],
                 "x-content-sha256:" + x_content_sha256,
                 "x-date:" + x_date,
             ]
         ),
         "",
         signed_headers_str,
         x_content_sha256,
         ]
    )

    # Print the normalized request for debugging and comparison.
    print(canonical_request_str)
    hashed_canonical_request = hash_sha256(canonical_request_str)

    # Print the hash value for debugging and comparison.
    print(hashed_canonical_request)
    credential_scope = "/".join([short_x_date, credential["region"], credential["service"], "request"])
    string_to_sign = "\n".join(["HMAC-SHA256", x_date, credential_scope, hashed_canonical_request])

    # Print the eventually calculated signature string for debugging and comparison.
    print(string_to_sign)
    k_date = hmac_sha256(credential["secret_access_key"].encode("utf-8"), short_x_date)
    k_region = hmac_sha256(k_date, credential["region"])
    k_service = hmac_sha256(k_region, credential["service"])
    k_signing = hmac_sha256(k_service, "request")
    signature = hmac_sha256(k_signing, string_to_sign).hex()

    sign_result["Authorization"] = "HMAC-SHA256 Credential={}, SignedHeaders={}, Signature={}".format(
        credential["access_key_id"] + "/" + credential_scope,
        signed_headers_str,
        signature,
    )
    header = {**header, **sign_result}
    # header = {**header, **{"X-Security-Token": SessionToken}}
    # Step 6: Write the signature into the HTTP header and send the HTTP request.
    r = requests.request(method=method,
                         url="https://{}{}".format(request_param["host"], request_param["path"]),
                         headers=header,
                         params=request_param["query"],
                         data=request_param["body"],
                         )
    return r.json()


if __name__ == "__main__":
    # response_body = request("Get", datetime.datetime.utcnow(), {}, {}, AK, SK, "ListUsers", None)
    # print(response_body)

    now = datetime.datetime.utcnow()

    # The format of the request body must be compatible with the Content-Type. 
    # For information about the content types used in API requests, refer to the related documentation. 
    # For example, if the content type is JSON, the request body must be in the following format: json.dumps(obj).
    response_body = request("GET", now, {"Limit": "2"}, {}, AK, SK, "ListUsers", None)
    print(response_body)

    response_body = request("POST", now, {"Limit": "10"}, {}, AK, SK, "ListUsers", "UnUseParam=ASDF")
    print(response_body)
