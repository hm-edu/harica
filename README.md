# Inofficial Client for the HARICA API

## Generate Cert with Auto Approval
```sh
./harica gen-cert \
    --domains "fancy.domain" \
    --requester-email "requester@fancy.domain" \
    --requester-password "password" \
    --requester-totp-seed "totp-seed" \
    --validator-email "validator@fancy.domain" \
    --validator-password "password" \
    --validator-totp-seed "totp-seed" \
    --csr "-----BEGIN CERTIFICATE REQUEST-----\nfoo-bar\n-----END CERTIFICATE REQUEST-----"
```

Beside using arguments you can also create a config file `cert-generator.yaml`:

```yaml
requester_email: ""
validator_email: ""
validator_totp_seed: ""
requester_totp_seed: ""
validator_password: ""
requester_password: ""
```

## Generate S/MIME via API key (bulk)

The `gen-cert smime` command supports an API-key mode (no requester/approver credentials or TOTP needed).

Note: `--api-key` and `--organization-id` are global (root) flags, so they can be placed before or after the subcommands; currently they are only used by `gen-cert smime`.

### Configuration precedence

Precedence is:

1. Flag
2. Environment variable
3. Config file

Supported settings:

- Flag: `--api-key`, Env: `HARICA_API_KEY`, Config: `api_key`
- Flag: `--organization-id`, Env: `HARICA_ORGANIZATION_ID`, Config: `organization_id`

### Usage

Using environment variables:

```sh
export HARICA_API_KEY="..."
export HARICA_ORGANIZATION_ID="..." # optional if autodiscovery finds exactly one org id

./harica gen-cert smime \
  --email "user@example.org" \
  --given-name "Jane" \
  --sur-name "Doe" \
  --friendly-name "Jane Doe" \
  --cert-type "email_only" \
  --csr "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"
```

Using flags:

```sh
./harica --api-key "..." --organization-id "..." gen-cert smime \
  --email "user@example.org" \
  --given-name "Jane" \
  --sur-name "Doe" \
  --friendly-name "Jane Doe" \
  --cert-type "email_only" \
  --csr "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"
```

Output in API-key mode:

- Default: prints the PEM certificate to stdout (PowerShell-friendly).
- `--output zip`: writes the ZIP to `./smime.zip` (or `--zip-out <path>`) and prints the ZIP path.

Note: if `organization_id` is not provided, the CLI will try to autodiscover it via `GET /cm/v1/admin/enterprises`. Autodiscovery only works when exactly one unique organization id is available to the API key.

### Find organization IDs

To list the organization IDs available to your API key:

```sh
./harica --api-key "..." org-ids
```


## Automatic Domain Validation using AXFR

In case you want to (re)validate several domains using DNS Challenges, you may use this module. To use this module, you must have a DNS server/provider that supports standard AXFR Updates to your zones. Right now, we consider all domains to be revalidated that expire in the next 30 days. Domains with a validity of more than 30 days get ignored by the tool.

### DNS Configuration

Please create a new YAML file with the following structure. 

```yaml
zones:
  - domain: "domain.de."
    nameserver: "dns-server:53"    
    tsig_key_name: "hm.edu."
    tsig_secret: "tsig_key"
    tsig_secret_alg: "hmac-md5.sig-alg.reg.int."
    net: "tcp"
  - domain: "domain.eu."
    nameserver: "dns-server:53"
    tsig_key_name: "tsig_key_name."
    tsig_secret: "tsig_key"
    tsig_secret_alg: "hmac-md5.sig-alg.reg.int."
    net: "tcp"
```

Alternative Algorithms are:

- `hmac-sha1.`
- `hmac-sha224.`
- `hmac-sha256.`
- `hmac-sha384.`
- `hmac-sha512.`
- `hmac-md5.sig-alg.reg.int.`


### Usage

Afterwards you can trigger the validation flow:

```sh
./harica validation \
    -u "harica-user" \
    -p "harica-password" \
    -t "harica-totp" \
    --imap-host "imap.server.com" \
    --imap-username "fancy-user" \
    --imap-password "fancy-password" \
    --domains "domain.de,domain.eu" \
    --email "fancy-user@server.com" \
    --dns "./path/to/dns-config" 
```


> [!WARNING]
> Please note that we do not recommend validating large batches at once since the code is not that reslient for failures or timeouts. Try to keep the batches smaller than 10 domains and start more batches sequentially.  