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

import os
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

__all__ = ["encrypt_secret"]


def encrypt_secret(key_path: str, value: str) -> str:
    """
    Encrypt the provided secret plain text and return base64 encoded ciphertext.
    """

    if not os.path.isfile(key_path):
        raise ValueError("Key file %s doesn't exist")

    with open(key_path, "rb") as fp:
        serialized_public_key = fp.read()

    public_key = serialization.load_pem_public_key(
        serialized_public_key,
        backend=None,
    )

    ciphertext = public_key.encrypt(
        value.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None
        ),
    )
    b64encoded = base64.b64encode(ciphertext)
    result = b64encoded.decode("utf-8")
    return result
