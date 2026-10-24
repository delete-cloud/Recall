# recall-opendal

A [Recall](https://github.com/samzong/Recall) remote provider using
[Apache OpenDAL](https://opendal.apache.org/). Requires **Recall 0.6.5 or newer**.
The extension manifest declares `protocol: 2` and `transport_version: 1`.

## Install and connect

Install the published package from Recall's official extension catalog:

```sh
recall ext install opendal
mkdir -p /absolute/path/to/recall-objects
recall remote connect --provider opendal --project all --host-name my-machine -- \
  --config-json '{"scheme":"fs","root":"/absolute/path/to/recall-objects"}'
recall remote sync --format json
```

Catalog installation supplies the managed binary and matching installation
record required by core. Version 0.1.0 becomes installable after the authorized
extension release publishes its catalog entry. Configure a private dedicated
bucket or prefix when using a network service.

## Configuration

`RECALL_OPENDAL_CONFIG` selects the target configuration file. Otherwise the
path is `~/.config/recall-opendal.json` on every platform, including macOS.
All JSON option values are strings, including booleans. Credentials are rejected
in every configuration entry point, including existing files, interactive
input, `--config-file`, and `--config-json`. Do not put secrets in configuration
files, arguments, endpoint URLs, or shell history.

Only these fields are accepted; unknown fields and OpenDAL aliases fail rather
than being silently ignored:

| Scheme | Accepted options |
| --- | --- |
| `fs` | `root`; optional `atomic_write_dir` restricted to `.recall-opendal-tmp` under that root |
| `s3` | `bucket`, `root`, `endpoint`, `region`, `credential_profile` or `profile`, `enable_virtual_host_style`, `disable_ec2_metadata`, `disable_list_objects_v2`, `default_storage_class`, `server_side_encryption`, `checksum_algorithm`, `enable_request_payer` |
| `webdav` | `endpoint`, `root`, `disable_create_dir` |
| `b2` | `bucket`, `bucket_id`, `root` |
| `memory` | `root` (ephemeral test service only) |

Filesystem roots must already exist and be absolute directories. The provider
resolves the root to a canonical path before constructing OpenDAL; a removed
root fails with `target_missing` instead of being recreated. Atomic staging
stays under that root and must not be a symbolic link. `memory` cannot persist
objects between one-shot provider calls.

Endpoints must be absolute HTTP(S) URLs without userinfo, query strings, or
fragments. Encoded authority forms are rejected. Cloudflare R2 and other
S3-compatible destinations use `scheme: "s3"` with the service's endpoint,
bucket, and region (`auto` for R2).

S3 uses OpenDAL's SDK environment/profile credential chain. `credential_profile`
is mapped to OpenDAL 0.59.5's `profile` field; supplying both selectors fails.
The SDK also supports `AWS_PROFILE`, `AWS_SHARED_CREDENTIALS_FILE`, and
`AWS_CONFIG_FILE`. Provision credentials through the SDK's secure local setup
before connecting:

```sh
recall remote connect --provider opendal --project all --host-name my-machine -- \
  --config-json '{"scheme":"s3","bucket":"recall-private","region":"us-east-1","credential_profile":"recall"}'
```

Pinned OpenDAL WebDAV and B2 do not load environment credentials themselves.
This provider reads `WEBDAV_USERNAME`, `WEBDAV_PASSWORD`, `WEBDAV_TOKEN`,
`B2_APPLICATION_KEY_ID`, and `B2_APPLICATION_KEY` from its process environment
and passes them to the SDK in memory. They are never persisted. B2 requires
both credential variables. Scheduled execution must provide the credentials
through its own secure runtime environment; shell profiles are not inherited.

Provider configuration can also be supplied as a file containing only the
non-sensitive fields above:

```sh
recall-opendal --recall-remote-configure --config-file /path/to/provider-target.json
recall-opendal --recall-remote-configure
```

Configuration performs a scoped read/list probe and saves the target atomically
with mode `0600` on Unix only on success. It does not verify get/put permission.
A failed replacement preserves the previous file. Interactive replacement shows
the proposed destination and requires `yes`; missing non-interactive parameters
fail immediately.

## Provider protocol

- `--recall-extension-manifest` prints `name: "opendal"`, crate `version`,
  `protocol: 2`, `min_recall: "0.6.5"`, `transport_version: 1`, and description.
- `--recall-remote-configure [--config-json JSON | --config-file PATH]`
  configures the target; diagnostics go to stderr.
- `--recall-remote-transport` reads one complete JSON request through stdin EOF
  and writes exactly one JSON response to stdout.

Each transport request supplies `transport_version: 1`, positive `timeout_ms`,
and an `operation` tag:

| Operation | Request fields | Result |
| --- | --- | --- |
| `probe` | none | `{"readable":true}` after a real scoped list |
| `list` | `prefix`, nullable `cursor`, `page_size` (1–1000) | `{"objects":[{"key":"v1/object","size":123}],"next_cursor":null}` |
| `get` | `key`, absolute `output_path`, `max_bytes` | `{"size":123}` |
| `put` | `key`, absolute `input_path`, `size`, lowercase `sha256` | `{"size":123,"sha256":"..."}` |

Success uses `{"transport_version":1,"result":{...}}` and exit status zero.
Failure uses `{"transport_version":1,"error":{"code":"permission","message":"..."}}`
and nonzero status. The status must agree with the envelope. Control messages
are limited to 2 MiB. Timeouts return `transient`; an in-flight remote write may
already have completed.

Keys are relative, 1–1024 bytes, and contain only `[a-z0-9/_-.]`. Empty, `.` and
`..` segments are forbidden. Nonempty prefixes end with `/`. Cursors are valid
keys within the prefix. Pages are lexically sorted and strictly after the
cursor; `next_cursor` is present and null only at the end. A malformed backend
key fails with `integrity`.

Ordered S3 listings stop after `page_size + 1` entries. Other backends retain
the smallest `page_size + 1` keys across a recursive listing, because OpenDAL's
listing limit is a backend hint; they may scan the remaining prefix per page.
Native `start_after` is used only when advertised. Concurrent writes do not
provide snapshot pagination.

Downloads enforce the declared size and `max_bytes`, then publish a private
temporary file without replacing an existing output. The output directory must
exist. Uploads snapshot and hash the source before publication. Existing remote
keys succeed only after their actual bytes match the supplied size and SHA-256;
different bytes fail with `conflict` and remain unchanged. Filesystem publication
uses an atomic no-clobber operation. Other services must advertise conditional
creation (`write_with_if_not_exists`); otherwise new-key puts fail closed with
`unavailable`. OpenDAL 0.59.5 WebDAV and B2 can support reads/listings but lack
that publication capability, so they cannot currently provide complete Recall
remote synchronization. S3-compatible services must implement conditional puts
correctly. Transfers use 4 MiB chunks and temporary disk up to the object size.

Errors use bounded category messages; raw SDK sources, URLs, response headers,
server payloads, and config parse values never enter diagnostics. HTTP 401,
typed SDK credential-invalid failures, and recognized structured credential
codes map to `authentication`. Ordinary access denial and opaque HTTP 403 stay
`permission`; unrelated SDK errors are not guessed to be credential failures.

## Build and verification

The workspace package requires Rust 1.91 or newer and pins OpenDAL **0.59.5**.
The blocking API runs within a small Tokio runtime. GCS and Azure Blob remain
deferred while their authentication dependencies include `rsa` affected by
RUSTSEC-2023-0071.

```sh
cargo build -p recall-opendal --release --locked
cargo fmt --all -- --check
cargo clippy -p recall-opendal --all-targets --locked -- -D warnings
cargo test -p recall-opendal --locked
python3 extensions/recall-opendal/scripts/verify-fs.py target/release/recall-opendal
```

Tests exercise isolated filesystem operations and local HTTP fixtures, including
immutable publication, concurrent puts, receipts, size/hash limits, lexical
pagination, missing targets, config rejection, redaction, and HTTP authentication
classification. They do not establish live cloud credentials, official catalog
publication, or two-host remote-sync acceptance.

### Real MinIO and two isolated Recall environments

With Python 3, Go 1.24+ and a built Recall 0.6.5 core binary:

```sh
python3 extensions/recall-opendal/scripts/verify-minio.py \
  --provider target/debug/recall-opendal --core target/debug/recall \
  --receipt /tmp/recall-opendal-minio.json
```

The script builds MinIO from upstream commit
`07c3a429bfed433e49018cb0f78a52145d4bedeb`, verifies the Go module checksum,
and records the binary hashes. It creates a loopback server, temporary data and
credentials, runs 17 provider checks, then uploads and downloads one synthetic
session through two isolated Recall homes and compares the exported message.
The homes contain managed-extension test records for the unpublished provider.
The server is stopped and temporary files removed when the run ends.

Pass `--baseline /path/to/previous/recall-opendal` to reproduce the old failures
before checking the candidate. `--minio /path/to/minio` uses a supplied binary
and records its hash; the caller is responsible for its source provenance.
These checks cover the local MinIO implementation and the core integration
fixture. Official catalog installation and joint testing against deployment
credentials remain release checks.
