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

import hashlib
import os
import shutil
import tempfile

__all__ = ["write_to_file", "get_secrets_lock_file_path", "get_template_file_lock_path"]


def write_to_file(file_path: str, permissions: int, content: bytes) -> None:
    # For security reasons we first write it to a temporary file, chmod it and then move it to a
    # final location
    fd, tmp_path = tempfile.mkstemp()
    os.chmod(tmp_path, permissions)

    try:
        try:
            os.write(fd, content)
        finally:
            os.close(fd)

        shutil.move(tmp_path, file_path)
    finally:
        if os.path.isfile(tmp_path):
            os.unlink(tmp_path)

    os.chmod(file_path, permissions)


def get_secrets_lock_file_path(secrets_path: str) -> str:
    secrets_path = os.path.abspath(os.path.expanduser(secrets_path))
    path_hash = hashlib.md5(secrets_path.encode("utf-8")).hexdigest()
    lock_path = "/tmp/compose-secrets-%s.lock" % (path_hash)

    return lock_path


def get_template_file_lock_path(template_path: str) -> str:
    template_path = os.path.abspath(os.path.expanduser(template_path))
    path_hash = hashlib.md5(template_path.encode("utf-8")).hexdigest()
    lock_path = "/tmp/compose-template-%s.lock" % (path_hash)

    return lock_path
