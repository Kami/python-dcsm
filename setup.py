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
import sys

from setuptools import find_packages, setup

from dist_utils import fetch_requirements, get_version_string

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUIREMENTS_FILE = os.path.join(BASE_DIR, "requirements.txt")
TESTS_REQUIREMENTS_FILE = os.path.join(BASE_DIR, "test-requirements.txt")

install_reqs, install_dep_links = fetch_requirements(REQUIREMENTS_FILE)
test_reqs, test_dep_links = fetch_requirements(TESTS_REQUIREMENTS_FILE)

sys.path.insert(0, BASE_DIR)

version = get_version_string(os.path.join(BASE_DIR, "dcsm/__init__.py"))


setup(
    name="dcsm",
    version=version,
    description=(
        "Simple Docker Compose secrets management using RSA asymmetric crypto + YAML secrets files"
    ),
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Tomaz Muraus",
    author_email="tomaz@tomaz.me",
    license="Apache 2.0",
    url="https://github.com/Kami/dcsm",
    include_package_data=True,
    packages=find_packages(exclude=["setuptools", "tests"]),
    provides=["dcsm"],
    install_requires=install_reqs,
    dependency_links=install_dep_links + test_dep_links,
    scripts=[
        "bin/dcsm-encrypt-secret",
        "bin/dcsm-decrypt-secret",
        "bin/dcsm-encrypt-secret-to-file",
        "bin/dcsm-remove-secret-from-file",
        "bin/dcsm-generate-key-pair",
        "bin/dcsm-render-template-file",
    ],
    test_suite="tests",
    classifiers=[
        "Development Status :: 3 - Alpha" "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
)
