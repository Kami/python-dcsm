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
import threading
import unittest
from unittest import mock

import yaml
from cryptography.hazmat.primitives import serialization
from jinja2 import UndefinedError

from dcsm.file_render import render_template_file, render_template_files

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIXTURES_DIR = os.path.abspath(os.path.join(BASE_DIR, "../fixtures"))

PRIVATE_KEY_1_PATH = os.path.join(FIXTURES_DIR, "keys/private_key_1_no_password.pem")
SECRETS_1_PATH = os.path.join(FIXTURES_DIR, "secrets/secrets1.yaml")
TEMPLATE_1_PATH = os.path.join(FIXTURES_DIR, "templates/docker-compose.yml.j2")
TEMPLATE_2_PATH = os.path.join(FIXTURES_DIR, "templates/docker-compose.yml.2.j2")

__all__ = ["FileRenderTestCase"]


class FileRenderTestCase(unittest.TestCase):
    def test_render_template_file_default_ensure_permissions_success(self):
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

        file_permissions = oct(os.stat(tmp_path).st_mode)[-3:]
        self.assertEqual(file_permissions, "600")

    def test_render_template_file_custom_ensure_permissions_success(self):
        _, tmp_path = tempfile.mkstemp()

        destination_path = render_template_file(
            key_path=PRIVATE_KEY_1_PATH,
            secrets_path=SECRETS_1_PATH,
            template_path=TEMPLATE_1_PATH,
            destination_path=tmp_path,
            ensure_permissions="740",
        )
        self.assertEqual(destination_path, tmp_path)

        rendered_template = self._get_file_content(tmp_path)
        self.assertTrue("- SECRET1=value 1" in rendered_template)
        self.assertTrue("- SECRET2=value 2" in rendered_template)
        self.assertTrue("- SECRET3=value 3" in rendered_template)

        file_permissions = oct(os.stat(tmp_path).st_mode)[-3:]
        self.assertEqual(file_permissions, "740")

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

    def test_batch_loads_yaml_and_key_once_and_decrypts_each_secret_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            template_a = os.path.join(tmp, "a.j2")
            template_b = os.path.join(tmp, "b.j2")
            out_a = os.path.join(tmp, "a.yml")
            out_b = os.path.join(tmp, "b.yml")
            with open(template_a, "w") as fp:
                fp.write("{{ secrets.KEY_ONE }} {{ secrets.KEY_ONE }}")
            with open(template_b, "w") as fp:
                fp.write("{{ secrets.KEY_ONE }} {{ secrets.KEY_THREE }}")
            original_yaml = yaml.safe_load
            original_load_key = serialization.load_pem_private_key
            with mock.patch("dcsm.file_render.yaml.safe_load", wraps=original_yaml) as yaml_load, \
                    mock.patch("dcsm.file_render.serialization.load_pem_private_key", wraps=original_load_key) as key_load, \
                    mock.patch("dcsm.file_render.decrypt_secret_with_key", wraps=__import__("dcsm.decryption", fromlist=["decrypt_secret_with_key"]).decrypt_secret_with_key) as decrypt:
                render_template_files(
                    key_path=PRIVATE_KEY_1_PATH,
                    secrets_path=SECRETS_1_PATH,
                    templates=[(template_a, out_a), (template_b, out_b)],
                )
            self.assertEqual(yaml_load.call_count, 1)
            self.assertEqual(key_load.call_count, 1)
            self.assertEqual(decrypt.call_count, 2)
            self.assertEqual(self._get_file_content(out_a), "value 1 value 1")
            self.assertEqual(self._get_file_content(out_b), "value 1 value 3")

    def test_batch_matches_legacy_single_file_output_and_keeps_strict_undefined(self):
        with tempfile.TemporaryDirectory() as tmp:
            template = os.path.join(tmp, "template.j2")
            single = os.path.join(tmp, "single.yml")
            batch = os.path.join(tmp, "batch.yml")
            with open(template, "w") as fp:
                fp.write("{{ secrets.KEY_TWO }}")
            render_template_file(PRIVATE_KEY_1_PATH, SECRETS_1_PATH, template, single)
            render_template_files(PRIVATE_KEY_1_PATH, SECRETS_1_PATH, [(template, batch)])
            self.assertEqual(self._get_file_content(single), self._get_file_content(batch))
            with open(template, "w") as fp:
                fp.write("{{ undefined_name }}")
            with self.assertRaises(UndefinedError) as error:
                render_template_files(PRIVATE_KEY_1_PATH, SECRETS_1_PATH, [(template, batch)])
            self.assertIn("undefined_name", str(error.exception))
            self.assertEqual(self._get_file_content(batch), "value 2")

    def test_unused_secrets_do_not_read_secret_or_key_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            template = os.path.join(tmp, "template.j2")
            output = os.path.join(tmp, "out")
            with open(template, "w") as fp:
                fp.write("plain text")
            render_template_files("missing-key", "missing-secrets", [(template, output)])
            self.assertEqual(self._get_file_content(output), "plain text")

    def test_batch_destination_permissions_and_reject_same_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            template = os.path.join(tmp, "template.j2")
            output = os.path.join(tmp, "out")
            with open(template, "w") as fp:
                fp.write("ok")
            render_template_files("", "", [(template, output)], ensure_permissions="640", dummy=True)
            self.assertEqual(oct(os.stat(output).st_mode)[-3:], "640")
            with self.assertRaisesRegex(ValueError, "cannot be the same"):
                render_template_files("", "", [(template, template)], dummy=True)
            relative_template = os.path.relpath(template)
            with self.assertRaisesRegex(ValueError, "cannot be the same"):
                render_template_files(
                    "", "", [(relative_template, os.path.abspath(template))], dummy=True
                )

    def test_batch_allows_per_destination_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            template = os.path.join(tmp, "template.j2")
            output_default = os.path.join(tmp, "default")
            output_private_exec = os.path.join(tmp, "private-exec")
            with open(template, "w") as fp:
                fp.write("ok")
            render_template_files(
                "",
                "",
                [(template, output_default), (template, output_private_exec, "700")],
                dummy=True,
            )
            self.assertEqual(oct(os.stat(output_default).st_mode)[-3:], "600")
            self.assertEqual(oct(os.stat(output_private_exec).st_mode)[-3:], "700")

    def test_batch_rejects_unsafe_permissions_before_writing_any_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            template = os.path.join(tmp, "template.j2")
            output_valid = os.path.join(tmp, "valid")
            output_unsafe = os.path.join(tmp, "unsafe")
            with open(template, "w") as fp:
                fp.write("ok")
            with self.assertRaisesRegex(ValueError, "writable"):
                render_template_files(
                    "",
                    "",
                    [(template, output_valid), (template, output_unsafe, "666")],
                    dummy=True,
                )
            self.assertFalse(os.path.exists(output_valid))
            self.assertFalse(os.path.exists(output_unsafe))
            with self.assertRaisesRegex(ValueError, "Setuid"):
                render_template_files(
                    "", "", [(template, output_unsafe, "4700")], dummy=True
                )

    def test_concurrent_writes_to_same_destination_are_complete_and_locked(self):
        with tempfile.TemporaryDirectory() as tmp:
            templates = []
            destination = os.path.join(tmp, "out")
            for name, contents in (("first", "first-complete"), ("second", "second-complete")):
                path = os.path.join(tmp, name + ".j2")
                with open(path, "w") as fp:
                    fp.write(contents)
                templates.append(path)
            barrier = threading.Barrier(2)
            errors = []

            def render(path):
                try:
                    barrier.wait()
                    render_template_file("", "", path, destination, dummy=True)
                except Exception as error:  # surfaced in the main test thread
                    errors.append(error)

            threads = [threading.Thread(target=render, args=(path,)) for path in templates]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(errors, [])
            self.assertIn(self._get_file_content(destination), {"first-complete", "second-complete"})

    def _get_file_content(self, file_path: str) -> str:
        with open(file_path, "r") as fp:
            return fp.read()
