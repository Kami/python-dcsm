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

from dcsm.file_render import render_template_file

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURES_DIR = os.path.abspath(os.path.join(BASE_DIR, "../fixtures"))

PRIVATE_KEY_1_PATH = os.path.join(FIXTURES_DIR, "keys/private_key_1_no_password.pem")
SECRETS_1_PATH = os.path.join(FIXTURES_DIR, "secrets/secrets1.yaml")
TEMPLATE_1_PATH = os.path.join(FIXTURES_DIR, "templates/docker-compose.yml.j2")
TEMPLATE_2_PATH = os.path.join(FIXTURES_DIR, "templates/docker-compose.yml.2.j2")

__all__ = ["FileRenderTestCase"]


class FileRenderTestCase(unittest.TestCase):
    def test_render_template_file_success(self):
        _, tmp_path = tempfile.mkstemp()

        destination_path = render_template_file(
            key_path=PRIVATE_KEY_1_PATH,
            secrets_path=SECRETS_1_PATH,
            template_path=TEMPLATE_1_PATH,
            destination_path=tmp_path,
        )
        self.assertEqual(destination_path, tmp_path)

        rendered_template = self._get_file_content(tmp_path)
        self.assertTrue("- SECRET1=value 1" in rendered_template)
        self.assertTrue("- SECRET2=value 2" in rendered_template)
        self.assertTrue("- SECRET3=value 3" in rendered_template)

    def test_render_template_references_inexistent_key_failure(self):
        _, tmp_path = tempfile.mkstemp()

        expected_msg = 'doesn\'t contain assignment for secret "INVALID"'
        self.assertRaisesRegex(
            ValueError,
            expected_msg,
            render_template_file,
            key_path=PRIVATE_KEY_1_PATH,
            secrets_path=SECRETS_1_PATH,
            template_path=TEMPLATE_2_PATH,
            destination_path=tmp_path,
        )

    def _get_file_content(self, file_path: str) -> str:
        with open(file_path, "r") as fp:
            return fp.read()
