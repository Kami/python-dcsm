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

import base64
import os
import unittest

from dcsm.decryption import decrypt_secret
from dcsm.encryption import encrypt_secret

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURES_DIR = os.path.abspath(os.path.join(BASE_DIR, "../fixtures"))

PRIVATE_KEY_1_PATH = os.path.join(FIXTURES_DIR, "keys/private_key_1_no_password.pem")
PUBLIC_KEY_1_PATH = os.path.join(FIXTURES_DIR, "keys/public_key_1_no_password.pem")

PRIVATE_KEY_2_PATH = os.path.join(FIXTURES_DIR, "keys/private_key_2_no_password.pem")
PUBLIC_KEY_2_PATH = os.path.join(FIXTURES_DIR, "keys/public_key_2_no_password.pem")

PRIVATE_KEY_1_WITH_PASSWORD_PATH = os.path.join(FIXTURES_DIR, "keys/private_key_1_password_foo.pem")
PUBLIC_KEY_1_WITH_PASSWORD_PATH = os.path.join(FIXTURES_DIR, "keys/public_key_1_password_foo.pem")

__all__ = ["EncryptDecryptTestCase"]


class EncryptDecryptTestCase(unittest.TestCase):
    def test_encrypt_decrypt_key_without_password(self):
        plaintext = "test hello world 1"

        ciphertext = encrypt_secret(key_path=PUBLIC_KEY_1_PATH, value=plaintext)
        b64decoded_ciphertext = base64.b64decode(ciphertext)
        self.assertTrue(ciphertext != plaintext)
        self.assertTrue(b64decoded_ciphertext != plaintext)

        # Valid key should work
        decrypted_plaintext = decrypt_secret(key_path=PRIVATE_KEY_1_PATH, secret=ciphertext)
        self.assertEqual(decrypted_plaintext, plaintext)

        # Invalid key should not work
        expected_msg = "Decryption failed"
        self.assertRaisesRegex(
            ValueError, expected_msg, decrypt_secret, key_path=PRIVATE_KEY_2_PATH, secret=ciphertext
        )

    def test_encrypt_decrypt_key_with_password(self):
        plaintext = "test hello world 2"

        ciphertext = encrypt_secret(key_path=PUBLIC_KEY_1_WITH_PASSWORD_PATH, value=plaintext)
        b64decoded_ciphertext = base64.b64decode(ciphertext)
        self.assertTrue(ciphertext != plaintext)
        self.assertTrue(b64decoded_ciphertext != plaintext)

        # Valid key should work
        decrypted_plaintext = decrypt_secret(
            key_path=PRIVATE_KEY_1_WITH_PASSWORD_PATH, secret=ciphertext, password="foo"
        )
        self.assertEqual(decrypted_plaintext, plaintext)

        # Missing password
        expected_msg = "Password was not given but private key is encrypted"
        self.assertRaisesRegex(
            TypeError,
            expected_msg,
            decrypt_secret,
            key_path=PRIVATE_KEY_1_WITH_PASSWORD_PATH,
            secret=ciphertext,
        )

        # Invalid password
        expected_msg = "Could not deserialize key data. The data may be in an incorrect format.*"
        self.assertRaisesRegex(
            ValueError,
            expected_msg,
            decrypt_secret,
            key_path=PRIVATE_KEY_1_WITH_PASSWORD_PATH,
            secret=ciphertext,
            password="invalid",
        )

        # Invalid key should not work
        expected_msg = "Decryption failed"
        self.assertRaisesRegex(
            ValueError, expected_msg, decrypt_secret, key_path=PRIVATE_KEY_2_PATH, secret=ciphertext
        )
