# -*- coding: utf-8 -*-
# Copyright 2020 Tomaz Muraus
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Optional

import os
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

__all__ = ["decrypt_secret"]


def decrypt_secret(key_path: str, secret: str, password: str = None) -> str:
    """
    Decrypt provided RSA encrypted and base64 encoded secret value.
    """
    if password:
        password_bytes: Optional[bytes] = password.encode("utf-8")
    else:
        password_bytes = None

    if not os.path.isfile(key_path):
        raise ValueError("Key file %s doesn't exist")

    with open(key_path, "rb") as fp:
        serialized_private_key = fp.read()

    private_key = serialization.load_pem_private_key(
        serialized_private_key,
        password=password_bytes,
        backend=None,
    )

    b64decoded = base64.b64decode(secret)

    plaintext = private_key.decrypt(
        b64decoded,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    result = plaintext.decode("utf-8")
    return result
