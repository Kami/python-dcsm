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
import shutil
import tempfile

from filelock import FileLock

from jinja2 import Environment

from dcsm.secrets_writer import decrypt_secret_from_file
from dcsm.utils import get_template_file_lock_path

__all__ = ["render_template_file"]


class DecryptSecretsDict(object):
    """
    Custom dictionary implementation which decrypts requested secret on access and provides
    user-friendly error messages.
    """

    def __init__(self, key_path: str, secrets_path: str, key_password: str = None) -> None:
        self._key_path = key_path
        self._secrets_path = secrets_path
        self._key_password = key_password

    def __getattr__(self, key):
        return decrypt_secret_from_file(
            key_path=self._key_path,
            secrets_path=self._secrets_path,
            key=key,
            key_password=self._key_password,
        )


def render_template_file(
    key_path: str,
    secrets_path: str,
    template_path: str,
    destination_path: str,
    key_password: str = None,
) -> str:
    """
    Render the provided docker compose template file, and replace secrets with decrypted secrets
    from the provided secrets file.
    """
    lock_path = get_template_file_lock_path(destination_path)
    lock = FileLock(lock_path, timeout=10)

    if template_path == destination_path:
        raise ValueError("Template and destination paths cannot be the same")

    with lock:
        # 1. Load compos template file
        with open(template_path, "rb") as fp:
            template_content = fp.read().decode("utf-8")

        # 2. Render the template with secrets
        secrets_dict = DecryptSecretsDict(
            key_path=key_path, secrets_path=secrets_path, key_password=key_password
        )
        template_context = {"secrets": secrets_dict}

        env = Environment()
        template = env.from_string(template_content)
        rendered_template = template.render(**template_context)

        # 3. Write rendered file to the destination path
        # For security reasons we first write it to a temporary file, chmod it and then move it to a
        # final location
        fd, tmp_path = tempfile.mkstemp()
        os.chmod(tmp_path, 0o600)

        try:
            try:
                os.write(fd, rendered_template.encode("utf-8"))
            finally:
                os.close(fd)

            shutil.move(tmp_path, destination_path)
        finally:
            if os.path.isfile(tmp_path):
                os.unlink(tmp_path)

        os.chmod(destination_path, 0o600)

    print("Rendered template saved to %s" % (destination_path))
    return destination_path
