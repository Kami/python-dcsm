#!/usr/bin/env python3
"""Compare repeated legacy-style renders with the shared batch renderer.

This is an informational microbenchmark, not a timing-sensitive test. It creates
an ephemeral RSA key and generated encrypted secrets and never prints plaintext.
"""

import argparse
import os
import sys
import tempfile
import time

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dcsm.file_render import render_template_file, render_template_files


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--files", type=int, default=25)
    parser.add_argument("--secrets-per-file", type=int, default=5)
    parser.add_argument("--iterations", type=int, default=3)
    args = parser.parse_args()
    if min(args.files, args.secrets_per_file, args.iterations) < 1:
        parser.error("all counts must be positive")

    with tempfile.TemporaryDirectory() as tmp:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_path = os.path.join(tmp, "private.pem")
        public_path = os.path.join(tmp, "public.pem")
        with open(private_path, "wb") as fp:
            fp.write(private_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
        with open(public_path, "wb") as fp:
            fp.write(private_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

        secret_values = {"BENCH_%d" % i: "synthetic-secret-%d" % i for i in range(args.secrets_per_file)}
        encrypted = {}
        for name, value in secret_values.items():
            encrypted[name] = __import__("base64").b64encode(private_key.public_key().encrypt(
                value.encode(), padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                              algorithm=hashes.SHA256(), label=None))).decode()
        secret_path = os.path.join(tmp, "secrets.yaml")
        with open(secret_path, "w") as fp:
            yaml.safe_dump(encrypted, fp)

        pairs = []
        for file_index in range(args.files):
            template = os.path.join(tmp, "template-%d.j2" % file_index)
            destination = os.path.join(tmp, "output-%d.yml" % file_index)
            with open(template, "w") as fp:
                fp.write("\n".join("{{ secrets.%s }}" % name for name in secret_values))
            pairs.append((template, destination))

        def legacy():
            for template, destination in pairs:
                render_template_file(private_path, secret_path, template, destination)

        def batched():
            render_template_files(private_path, secret_path, pairs)

        # Warm imports and filesystem caches, then report medians.
        legacy()
        batched()
        samples = {"legacy": [], "batch": []}
        for _ in range(args.iterations):
            for name, fn in (("legacy", legacy), ("batch", batched)):
                started = time.perf_counter()
                fn()
                samples[name].append(time.perf_counter() - started)
        for name in ("legacy", "batch"):
            ordered = sorted(samples[name])
            median = ordered[len(ordered) // 2]
            print("%s median: %.4fs" % (name, median))
        old = sorted(samples["legacy"])[len(samples["legacy"]) // 2]
        new = sorted(samples["batch"])[len(samples["batch"]) // 2]
        print("speedup: %.2fx" % (old / new if new else float("inf")))
        print("workload: %d files, %d secrets/file, %d iterations" % (
            args.files, args.secrets_per_file, args.iterations))


if __name__ == "__main__":
    main()
