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
import time
import getpass
import socket
import shutil
import tempfile
import datetime

import yaml

from filelock import FileLock

from dcsm.encryption import encrypt_secret
from dcsm.decryption import decrypt_secret
from dcsm.utils import write_to_file
from dcsm.utils import get_secrets_lock_file_path

__all__ = ["encrypt_and_write_to_file", "remove_secret_from_file"]


class BackupFile(object):
    def __init__(self, file_path):
        self.file_path = file_path
        _, self.tmp_path = tempfile.mkstemp(suffix=".bak")
        os.chmod(self.tmp_path, 0o600)

    def __enter__(self):
        if os.path.isfile(self.file_path):
            shutil.copyfile(self.file_path, self.tmp_path)

    def __exit__(self, type, value, traceback):
        os.unlink(self.tmp_path)


def encrypt_and_write_to_file(key_path: str, secrets_path: str, key: str, value: str) -> None:
    """
    Encrypt secret value and write it to the provided YAML file with secrets.
    """
    lock_path = get_secrets_lock_file_path(secrets_path)
    lock = FileLock(lock_path, timeout=10)

    with lock:
        # 1. Encrypt the secret
        ciphertext = encrypt_secret(key_path=key_path, value=value)

        # 2. Read existing file content
        content = get_file_content(secrets_path)

        now_dt = datetime.datetime.utcnow()
        now_ts = int(time.time())
        now_string = now_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        updated_at = "%s # %s" % (now_string, now_ts)

        # 3. Merge the new value in
        updated_by = "%s@%s" % (getpass.getuser(), socket.gethostname())
        content["%s_updated_at" % (key)] = updated_at
        content["%s_updated_by" % (key)] = updated_by
        content[key] = ciphertext
        content["updated_at"] = now_ts
        content = dict(sorted(content.items()))

        # 4. Save updated file content on dsik
        result = yaml.safe_dump(content, default_flow_style=False, explicit_start=True)

        with BackupFile(secrets_path):
            write_to_file(file_path=secrets_path, permissions=0o600, content=result.encode("utf-8"))

        print('Encrypted secret "%s" written to %s' % (key, secrets_path))


def remove_secret_from_file(secrets_path: str, key: str) -> bool:
    lock_path = get_secrets_lock_file_path(secrets_path)
    lock = FileLock(lock_path, timeout=10)

    with lock:
        content = get_file_content(secrets_path)

        if key not in content:
            raise ValueError('File %s doesn\'t contain secret "%s"' % (secrets_path, key))

        keys_to_remove = [
            key,
            "%s_updated_at" % (key),
            "%s_updated_by" % (key),
        ]

        for key_name in keys_to_remove:
            if key_name in content:
                del content[key_name]

        now_ts = int(time.time())

        content["updated_at"] = now_ts
        content = dict(sorted(content.items()))
        result = yaml.safe_dump(content, default_flow_style=False, explicit_start=True)

        with BackupFile(secrets_path):
            write_to_file(file_path=secrets_path, permissions=0o600, content=result.encode("utf-8"))

    print('Secret "%s" removed from file %s' % (key, secrets_path))
    return True


def decrypt_secret_from_file(
    key_path: str, secrets_path: str, key: str, key_password: str = None
) -> str:
    content = get_file_content(secrets_path)

    if key not in content:
        raise ValueError(
            'File path %s doesn\'t contain assignment for secret "%s"' % (secrets_path, key)
        )

    plaintext = decrypt_secret(key_path=key_path, secret=content[key], password=key_password)
    return plaintext


def get_file_content(file_path: str) -> dict:
    if not os.path.isfile(file_path):
        return {}

    with open(file_path, "rb") as fp:
        result = yaml.safe_load(fp)

    return result or {}
