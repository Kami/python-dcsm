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

from dcsm.keygen import generate_key_pair

__all__ = ["KeyGenTestCase"]


class KeyGenTestCase(unittest.TestCase):
    def test_generate_key_pair_without_password(self):
        tmp_path = tempfile.mkdtemp()

        private_key_path, public_key_path = generate_key_pair(path=tmp_path)
        self.assertTrue(os.path.isfile(private_key_path))
        self.assertTrue(os.path.isfile(public_key_path))

        private_key_content = self._get_file_content(private_key_path)
        public_key_content = self._get_file_content(public_key_path)

        self.assertTrue(public_key_content.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(private_key_content.startswith("-----BEGIN RSA PRIVATE KEY-----"))

    def test_generate_key_pair_wit_password(self):
        tmp_path = tempfile.mkdtemp()

        private_key_path, public_key_path = generate_key_pair(path=tmp_path, password="password")
        self.assertTrue(os.path.isfile(private_key_path))
        self.assertTrue(os.path.isfile(public_key_path))

        private_key_content = self._get_file_content(private_key_path)
        public_key_content = self._get_file_content(public_key_path)

        self.assertTrue(public_key_content.startswith("-----BEGIN PUBLIC KEY-----"))
        self.assertTrue(private_key_content.startswith("-----BEGIN ENCRYPTED PRIVATE KEY-----"))

    def _get_file_content(self, file_path: str) -> str:
        with open(file_path, "r") as fp:
            return fp.read()
