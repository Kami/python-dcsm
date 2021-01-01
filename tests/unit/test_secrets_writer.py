#!/usr/bin/env python3
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
import tempfile
import unittest

import yaml

from dcsm.secrets_writer import encrypt_and_write_to_file
from dcsm.secrets_writer import remove_secret_from_file
from dcsm.secrets_writer import decrypt_secret_from_file
from dcsm.decryption import decrypt_secret
from dcsm.utils import get_template_file_lock_path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURES_DIR = os.path.abspath(os.path.join(BASE_DIR, "../fixtures"))

PRIVATE_KEY_1_PATH = os.path.join(FIXTURES_DIR, "keys/private_key_1_no_password.pem")
PUBLIC_KEY_1_PATH = os.path.join(FIXTURES_DIR, "keys/public_key_1_no_password.pem")
SECRETS_1_PATH = os.path.join(FIXTURES_DIR, "secrets/secrets1.yaml")

__all__ = ["SecretsWriterTestCase"]


class SecretsWriterTestCase(unittest.TestCase):
    def test_encrypt_and_write_to_file_new_file(self):
        _, tmp_path = tempfile.mkstemp()

        lock_path = get_template_file_lock_path(tmp_path)
        self.assertFalse(os.path.isfile(lock_path))

        encrypt_and_write_to_file(
            key_path=PUBLIC_KEY_1_PATH, secrets_path=tmp_path, key="key1", value="value 1"
        )

        content = yaml.safe_load(self._get_file_content(tmp_path))
        self.assertTrue("key1" in content)
        self.assertTrue("key1_updated_at" in content)
        self.assertTrue("key1_updated_by" in content)

        decrypted_key1 = decrypt_secret(key_path=PRIVATE_KEY_1_PATH, secret=content["key1"])
        self.assertEqual(decrypted_key1, "value 1")

        # Verify lock file was cleaned up
        self.assertFalse(os.path.isfile(lock_path))

        # Append another entry
        encrypt_and_write_to_file(
            key_path=PUBLIC_KEY_1_PATH, secrets_path=tmp_path, key="KEY_FOO", value="bar"
        )

        content = yaml.safe_load(self._get_file_content(tmp_path))
        self.assertTrue("key1" in content)
        self.assertTrue("KEY_FOO" in content)

        decrypted_key1 = decrypt_secret(key_path=PRIVATE_KEY_1_PATH, secret=content["key1"])
        decrypted_key_foo = decrypt_secret(key_path=PRIVATE_KEY_1_PATH, secret=content["KEY_FOO"])
        self.assertEqual(decrypted_key1, "value 1")
        self.assertEqual(decrypted_key_foo, "bar")

        # Test updating a value with the same key
        encrypt_and_write_to_file(
            key_path=PUBLIC_KEY_1_PATH, secrets_path=tmp_path, key="key1", value="value new!"
        )

        content = yaml.safe_load(self._get_file_content(tmp_path))
        self.assertTrue("key1" in content)
        self.assertTrue("key1_updated_at" in content)
        self.assertTrue("key1_updated_by" in content)

        decrypted_key1 = decrypt_secret(key_path=PRIVATE_KEY_1_PATH, secret=content["key1"])
        self.assertEqual(decrypted_key1, "value new!")

        # Test deleting an entry
        self.assertTrue(remove_secret_from_file(secrets_path=tmp_path, key="key1"))

        content = yaml.safe_load(self._get_file_content(tmp_path))
        self.assertFalse("key1" in content)
        self.assertFalse("key1_updated_at" in content)
        self.assertFalse("key1_updated_by" in content)

        # Key doesn't exist
        expected_msg = 'doesn\'t contain secret "invalid"'
        self.assertRaisesRegex(
            ValueError, expected_msg, remove_secret_from_file, secrets_path=tmp_path, key="invalid"
        )

    def test_decrypt_secret_from_file_success(self):
        decrypted_key = decrypt_secret_from_file(
            key_path=PRIVATE_KEY_1_PATH, secrets_path=SECRETS_1_PATH, key="KEY_ONE"
        )
        self.assertEqual(decrypted_key, "value 1")

        decrypted_key = decrypt_secret_from_file(
            key_path=PRIVATE_KEY_1_PATH, secrets_path=SECRETS_1_PATH, key="KEY_THREE"
        )
        self.assertEqual(decrypted_key, "value 3")

    def _get_file_content(self, file_path: str) -> str:
        with open(file_path, "r") as fp:
            return fp.read()
