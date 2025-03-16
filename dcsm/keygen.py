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
from typing import Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from dcsm.utils import write_to_file

__all__ = ["generate_key_pair"]

KEY_SIZE = 8192


def generate_key_pair(
    path: str, password: Optional[str] = None, overwrite: bool = False
) -> Tuple[str, str]:
    """
    Generate a new public and private key pair and write result to a file.
    """
    assert KEY_SIZE >= 4096
    print("Generating 8192 bit key pair, this may take a while...")

    private_key_path = os.path.expanduser(os.path.join(path, "private_key.pem"))
    public_key_path = os.path.expanduser(os.path.join(path, "public_key.pem"))

    if os.path.exists(private_key_path) and not overwrite:
        raise ValueError(
            "File %s exists and --overwrite flag was not used, aborting." % (private_key_path)
        )

    if os.path.exists(public_key_path) and not overwrite:
        raise ValueError(
            "File %s exists and --overwrite flag was not used, aborting." % (public_key_path)
        )

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=KEY_SIZE, backend=default_backend()
    )
    public_key = private_key.public_key()

    if password:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
        )
    else:
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    write_to_file(file_path=private_key_path, permissions=0o600, content=private_key_pem)
    write_to_file(file_path=public_key_path, permissions=0o600, content=public_key_pem)

    print("Private key saved to %s" % (private_key_path))
    print("Public key saved to %s" % (public_key_path))

    return (private_key_path, public_key_path)
