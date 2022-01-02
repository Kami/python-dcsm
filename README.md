# Simple File Based Docker Compose Secrets Management (dcsm)

[![CI](https://github.com/Kami/python-dcsm/workflows/CI/badge.svg?branch=master)](https://github.com/Kami/python-dcsm/actions) 
[![codecov](https://codecov.io/gh/Kami/python-dcsm/branch/master/graph/badge.svg?token=TQ1SVRY8Z1)](https://codecov.io/gh/Kami/python-dcsm)

This repository includes scripts which allow you to encrypt various secrets which can then be
used inside Docker compose template files (for environment variable values, etc.)

It's meant to be used in simple single host Docker compose deployment scenarios where something
like Docker Swarm or Kubernetes is not used so you can't utilize Swarm / Kubernetes secrets
management.

For encryption, RSA asymmetric cryptography is used. This means that only your server where
Docker compose and Docker containers are running needs to have access to the private key which
is used to decrypt encrypted secrets.

Keep in mind that even though this tool was developed primarily with docker compose use case in
mind, you can also use it to render other template files with secrets (think various application
specific config files, etc.).

## Usage / Workflow

The general Docker compose workflow stays pretty much the same as before. Only difference is
that, you now need a file named ``docker-compose.yml.j2`` (``.j2`` extension is used, because
Jinja templating engine is used).

docker-compose.yml.j2 file content stays the same as with original Docker compose format, only
difference is that you can use the following Jinja notation as shown bellow to reference secrets:

```yaml
version: "3"

services:
  service_1:
    ...
    environment:
      - SECRET1={{secrets.key1}}
      - SECRET2={{secrets.key2}}
      - SECRET3={{secrets.key3}}
    ...
```

In this example, ``SECRET1`` environment variable references a secret with key ``key1``.

Since the whole file is rendered as Jinja template it means you can use Jinja notation anywhere in
the file.

For example:

```yaml
version: "3"

services:
  redis:
    image: redis:5.0.10-alpine
    command: redis-server --requirepass {{ secrets.REDIS_HOST_PASSWORD }}
    ...
```

General workflow would look something like this.

# 1. Generate Key Pair

```bash
dcs-generate-key-pair --path $(pwd) --password "mySecretPassword1234"
```

This will generate ``private_key.pem`` and ``public_key.pem`` file in the current working
directory. Since ``--password`` flag is used, private key file is also encrypted and protected
with a password.

After you have generated a key pair, you should backup private key in a safe space and also upload
it to your server where docker compose and containers will run (make sure permissions for that file
are locked down - e.g. 600).

# 2. Create YAML File With Encrypted Secrets

Now that you have created a key pair and securely stored the private key, you can use public
key to encrypt your secrets.

```bash
dcs-encrypt-secret-to-file --key-path $(pwd)/public_key.yaml --secrets-path $(pwd)/secrets.yaml REDIS_HOST_PASSWORD super_secret_value
```

``--secrets-path`` argument specifies path to the YAML file where encrypted secrets will be stored.

Since this file contains encrypted secret values, you can safely store it inside the same (private)
repo where you store your docker compose definition files.

To remove a secret from a file, you can use ``dcs-remove-secret-from-file`` command or simply
manually remove secret from a file with your text editor of choice.

# 3. Update docker-compose.yml.j2 file to reference secret values using Jinja notation

```yaml
version: "3"

services:
  service_1:
    ...
    environment:
      - SECRET1={{secrets.key_one}}
    ...
```

# 4. Update your deployment script to render the docker-compose.yml.j2 template file

As a last step, you need to modify your deployment pipeline to actually decrypt the secrets and
render the ``docker-compose.yml.j2`` template file to ``docker-compose.yml`` with decrypted
secrets on the server where the Docker compose commands and containers will run.

For that you can use, ``dcs-render-template-file`` script. You also need access to the file
with encrypted secrets (usually that will be stored in a git repository) and access to the
private key.

As far as more concrete instructions - it depends on your pipeline setup and workflow (push vs
pull, etc.).

For example, you could have a script which periodically (via cron or systemd timers) pulls
down the content from your docker compose git repo, renders the file and (re)start the
containers.

As an alternative, you could also use a Github Actions CI/CD pipeline to achieve that or a
git hook.

```bash
cd /path/to/docker-compose-repo
git pull origin master

# Do this for each docker-compose.yml.j2 file
cd compose_service_1
dcs-render-template-file --key-path ~/.secrets/private_key.pem --secrets-path ~/compose-secrets/secrets.yaml \
  --template-path docker-compose.yml.j2 --destination-path docker-compose.yml

docker-compose up -d --build
```

This will write ``docker-compose.yml`` file with decrypted secrets. Since this file will contains
decrypted secrets, you need to ensure permissions are locked down (e.g. 600) and also make sure
it's in ``.gitignore`` so it doesn't get accidentally committed to the repo or similar.

## Warning

This code has not been audited for security vulnerabilities and bugs so use it at your own risk!

I take no responsibility and you have been warned.

## Limitations

1. Currently no key rotation scheme is implemented and supported
2. Asymmetric crypto without any MAC scheme is used which means that anyone with access to the
   public key and write access to secrets file can create / update secrets (aka there is no
   guarantee for integrity and authenticity of the secrets data). For simplicity, this project
   assumed secrets file is only writable by authorized uses. To be able to guarantee integrity and
   authenticity we would either need to use multiple RSA keys (one for decryption on the server
   side and X for users who are authorized to write secrets) or use symmetric crypto. This would
   change the threat model and make code more complex.
3. Maximum size of unecrypted secret is ~512 bytes (4096 bit RSA key).
4. When writting rendered template files, to avoid race conditions, first a temporary file is
   created in a safe manner, second permissions are ensured, third rendered values are written and
   at the very end, file is moved to the final location. Having said that, you are still encouraged
   to set a safe default umask for new files when using this script (e.g. ``umask 077``).
