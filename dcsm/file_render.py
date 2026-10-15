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
from typing import Dict, Iterable, Optional, Sequence, Tuple

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from filelock import FileLock
from jinja2 import Environment, StrictUndefined

from dcsm.decryption import decrypt_secret_with_key
from dcsm.utils import get_template_file_lock_path

__all__ = ["render_template_file", "render_template_files"]


class RenderSecrets:
    """Secrets mapping shared across a render batch, with lazy I/O and memoization."""

    def __init__(self, key_path: str, secrets_path: str, key_password: Optional[str] = None):
        self._key_path = key_path
        self._secrets_path = secrets_path
        self._key_password = key_password
        self._content: Optional[dict] = None
        self._private_key: Optional[RSAPrivateKey] = None
        self._decrypted: Dict[str, str] = {}

    def __getattr__(self, key: str) -> str:
        if key.startswith("_"):
            raise AttributeError(key)
        if key in self._decrypted:
            return self._decrypted[key]
        if self._content is None:
            if not os.path.isfile(self._secrets_path):
                raise ValueError("File %s doesn't exist" % (self._secrets_path))
            with open(self._secrets_path, "rb") as fp:
                self._content = yaml.safe_load(fp) or {}
        if key not in self._content:
            raise ValueError(
                'File path %s doesn\'t contain assignment for secret "%s"'
                % (self._secrets_path, key)
            )
        if self._private_key is None:
            if not os.path.isfile(self._key_path):
                raise ValueError("Key file %s doesn't exist" % (self._key_path))
            with open(self._key_path, "rb") as fp:
                serialized_key = fp.read()
            self._private_key = serialization.load_pem_private_key(
                serialized_key,
                password=self._key_password.encode("utf-8") if self._key_password else None,
                backend=None,
            )  # type: ignore[assignment]
        result = decrypt_secret_with_key(self._private_key, self._content[key])
        self._decrypted[key] = result
        return result


class DummySecretsDict:
    """Class which always returns a fixed value for every key."""

    def __init__(self, key_value: str) -> None:
        self._key_value = key_value

    def __getattr__(self, key: str) -> str:
        if key.startswith("_"):
            raise AttributeError(key)
        return self._key_value


def _render_one(
    template_path: str,
    destination_path: str,
    ensure_permissions: str,
    secrets_dict: object,
) -> str:
    if template_path == destination_path:
        raise ValueError("Template and destination paths cannot be the same")
    lock = FileLock(get_template_file_lock_path(destination_path), timeout=10)
    with lock:
        with open(template_path, "rb") as fp:
            template_content = fp.read().decode("utf-8")
        template = Environment(undefined=StrictUndefined).from_string(template_content)
        rendered_template = template.render(secrets=secrets_dict)

        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(os.path.abspath(destination_path)))
        try:
            os.fchmod(fd, int(ensure_permissions, 8))
            with os.fdopen(fd, "wb") as fp:
                fp.write(rendered_template.encode("utf-8"))
            shutil.move(tmp_path, destination_path)
        finally:
            if os.path.isfile(tmp_path):
                os.unlink(tmp_path)
        os.chmod(destination_path, int(ensure_permissions, 8))
    print("Rendered template saved to %s" % (destination_path))
    return destination_path


def render_template_files(
    key_path: str,
    secrets_path: str,
    templates: Iterable[Tuple[str, str]],
    ensure_permissions: str = "600",
    key_password: Optional[str] = None,
    dummy: bool = False,
) -> Sequence[str]:
    """Render (template, destination) pairs sharing one lazy secret/key cache."""
    secrets_dict = DummySecretsDict("dummy") if dummy else RenderSecrets(
        key_path=key_path, secrets_path=secrets_path, key_password=key_password
    )
    results = []
    for template_path, destination_path in templates:
        results.append(
            _render_one(
                template_path, destination_path, ensure_permissions, secrets_dict
            )
        )
    return results


def render_template_file(
    key_path: str,
    secrets_path: str,
    template_path: str,
    destination_path: str,
    ensure_permissions: str = "600",
    key_password: Optional[str] = None,
    dummy: bool = False,
) -> str:
    """Render one template, replacing requested secrets from the encrypted YAML file."""
    return render_template_files(
        key_path=key_path,
        secrets_path=secrets_path,
        templates=[(template_path, destination_path)],
        ensure_permissions=ensure_permissions,
        key_password=key_password,
        dummy=dummy,
    )[0]
