#!/usr/bin/env python3
"""Isolated real-MinIO provider verification; all credentials/data are temporary.

Without --minio, builds the pinned upstream source using the installed Go toolchain.
Optional --baseline runs the same checks against a previously built provider.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

MINIO_MODULE = "github.com/minio/minio@v0.0.0-20250907161309-07c3a429bfed"
MINIO_COMMIT = "07c3a429bfed433e49018cb0f78a52145d4bedeb"
MINIO_SUM = "h1:deu0m9BiyqnMbGWfJi1PpVyotSXlDnTmRIme1cUXnxo="


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def signed_request(endpoint, method, path, content, access, secret):
    """SigV4 setup/oracle requests; provider operations use the actual OpenDAL SDK."""
    now = datetime.datetime.now(datetime.timezone.utc)
    stamp, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    host = endpoint.removeprefix("http://")
    digest = hashlib.sha256(content).hexdigest()
    headers = f"host:{host}\nx-amz-content-sha256:{digest}\nx-amz-date:{stamp}\n"
    names = "host;x-amz-content-sha256;x-amz-date"
    canonical = "\n".join([method, path, "", headers, names, digest])
    scope = f"{day}/us-east-1/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope,
                         hashlib.sha256(canonical.encode()).hexdigest()])
    key = ("AWS4" + secret).encode()
    for value in [day, "us-east-1", "s3", "aws4_request"]:
        key = hmac.new(key, value.encode(), hashlib.sha256).digest()
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    authorization = f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={names}, Signature={signature}"
    request = urllib.request.Request(endpoint + path, method=method,
        data=content if method == "PUT" else None,
        headers={"Host": host, "x-amz-content-sha256": digest, "x-amz-date": stamp,
                 "Authorization": authorization})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def check_provider(binary, root, endpoint, bucket, access, secret, label):
    config = root / f"{label}.json"
    target = {"scheme": "s3", "bucket": bucket, "region": "us-east-1",
              "endpoint": endpoint, "root": label, "disable_ec2_metadata": "true"}
    env = {"PATH": os.environ.get("PATH", ""), "HOME": str(root / "sdk-home"),
           "RECALL_OPENDAL_CONFIG": str(config), "AWS_ACCESS_KEY_ID": access,
           "AWS_SECRET_ACCESS_KEY": secret, "AWS_EC2_METADATA_DISABLED": "true"}
    (root / "sdk-home").mkdir(exist_ok=True)
    configured = subprocess.run([str(binary), "--recall-remote-configure", "--config-json",
        json.dumps(target)], env=env, capture_output=True, text=True, timeout=30)
    assert configured.returncode == 0, "MinIO configuration failed"
    saved = config.read_text()
    assert access not in saved and secret not in saved
    results = {"configuration_without_saved_credentials": True}

    def request(operation, extra_env=None, **fields):
        payload = dict(transport_version=1, timeout_ms=30000, operation=operation, **fields)
        result = subprocess.run([str(binary), "--recall-remote-transport"],
            input=json.dumps(payload), text=True, capture_output=True,
            env=dict(env, **(extra_env or {})), timeout=40)
        value = json.loads(result.stdout)
        assert result.returncode == (0 if "result" in value else 1), value
        assert secret not in result.stdout + result.stderr
        return value

    def put(key, content):
        source = root / f"input-{secrets.token_hex(8)}"
        source.write_bytes(content)
        return request("put", key=key, input_path=str(source), size=len(content),
                       sha256=hashlib.sha256(content).hexdigest())

    def actual(key):
        return signed_request(endpoint, "GET", f"/{bucket}/{label}/{key}", b"", access, secret)

    results["probe"] = request("probe").get("result") == {"readable": True}
    for name, content in [("empty", b""), ("single", b"original"),
                          ("multipart", bytes(range(251)) * 50134)]:
        key = f"v1/{name}"
        first = put(key, content)
        results[f"{name}_initial_bytes"] = "result" in first and actual(key) == content
        results[f"{name}_identical_retry"] = "result" in put(key, content)
        other = b"x" * len(content) if content else b"different"
        conflict = put(key, other)
        results[f"{name}_different_conflict"] = conflict.get("error", {}).get("code") == "conflict" and actual(key) == content
        if content:
            signed_request(endpoint, "PUT", f"/{bucket}/{label}/{key}", other, access, secret)
            retry = put(key, content)
            results[f"{name}_corruption_detected"] = retry.get("error", {}).get("code") == "conflict" and actual(key) == other

    values = [bytes([65 + i]) * (1024 * 1024 + i) for i in range(8)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda value: put("v1/race", value), values))
    winners = [i for i, value in enumerate(responses) if "result" in value]
    results["concurrent_single_winner"] = len(winners) == 1 and actual("v1/race") == values[winners[0]]
    results["concurrent_losers_conflict"] = all("result" in value or value.get("error", {}).get("code") == "conflict" for value in responses)

    for i in range(9):
        signed_request(endpoint, "PUT", f"/{bucket}/{label}/pages/{i:02}", bytes([i]), access, secret)
    cursor, keys = None, []
    while True:
        page = request("list", prefix="pages/", cursor=cursor, page_size=2)["result"]
        keys.extend(x["key"] for x in page["objects"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
        assert len(keys) <= 9, "pagination did not terminate"
    results["complete_pagination"] = keys == [f"pages/{i:02}" for i in range(9)]
    rejected = request("probe", extra_env={"AWS_ACCESS_KEY_ID": "invalid-isolated-test-key"})
    results["rejected_credentials_authentication"] = rejected.get("error", {}).get("code") == "authentication"
    return results, env, target


def check_core(core, provider, root, endpoint, bucket, access, secret):
    env = {"PATH": os.environ.get("PATH", ""), "AWS_ACCESS_KEY_ID": access,
           "AWS_SECRET_ACCESS_KEY": secret, "AWS_EC2_METADATA_DISABLED": "true"}
    receipts = []
    for label in ["writer", "reader"]:
        home = root / label
        home.mkdir()
        data = home / ("Library/Application Support" if os.uname().sysname == "Darwin" else ".local/share")
        ext = data / "recall/extensions"
        (ext / "bin").mkdir(parents=True)
        shutil.copy2(provider, ext / "bin/recall-opendal")
        # Unpublished-provider test fixture, as documented by extensions/AGENTS.md.
        (ext / "installed.json").write_text(json.dumps({"schema": 1,
            "extensions": {"opendal": {"version": "0.1.0", "description": "isolated fixture"}}}))
        current = dict(env, HOME=str(home), XDG_DATA_HOME=str(home / ".local/share"),
            XDG_CONFIG_HOME=str(home / ".config"), RECALL_OPENDAL_CONFIG=str(home / "provider.json"))
        if label == "writer":
            session = home / ".codex/sessions/2026/10/25/rollout-2026-10-25T00-00-00-11111111-2222-4333-8444-555555555555.jsonl"
            session.parent.mkdir(parents=True)
            rows = [
                {"timestamp": "2026-10-25T00:00:00Z", "type": "session_meta",
                 "payload": {"id": "11111111-2222-4333-8444-555555555555", "timestamp": "2026-10-25T00:00:00Z", "cwd": str(home)}},
                {"timestamp": "2026-10-25T00:00:01Z", "type": "event_msg",
                 "payload": {"type": "user_message", "message": "Isolated catalog provider verification"}},
            ]
            session.write_text("\n".join(json.dumps(x) for x in rows) + "\n")
        target = {"scheme": "s3", "bucket": bucket, "region": "us-east-1", "endpoint": endpoint,
                  "root": "core-roundtrip", "disable_ec2_metadata": "true"}
        connect = subprocess.run([str(core), "remote", "connect", "--provider", "opendal",
            "--project", "all", "--host-name", label, "--", "--config-json", json.dumps(target)],
            env=current, capture_output=True, text=True, timeout=60)
        assert connect.returncode == 0, f"core connect failed: {connect.stderr}"
        result = subprocess.run([str(core), "remote", "sync", "--format", "json"],
            env=current, capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, f"core sync failed: {result.stderr}"
        summary = json.loads(result.stdout)
        exported = subprocess.run([str(core), "export", "--project", "all", "--include", "metadata,messages"],
            env=current, capture_output=True, text=True, timeout=30)
        assert exported.returncode == 0, exported.stderr
        records = [json.loads(line) for line in exported.stdout.splitlines() if line.strip()]
        messages = [message["content"] for record in records for message in record.get("messages", [])]
        assert messages == ["Isolated catalog provider verification"], {"host": label, "messages": messages}
        receipts.append({"host": label, "summary": summary, "sessions": len(records), "message_bytes_verified": True})
    assert receipts[0]["summary"]["uploaded"] > 0, receipts
    assert receipts[1]["summary"]["downloaded"] > 0, receipts
    return receipts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", type=Path, default=Path("target/debug/recall-opendal"))
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--minio", type=Path)
    parser.add_argument("--core", type=Path)
    parser.add_argument("--receipt", type=Path)
    args = parser.parse_args()
    report = {"tests": {}, "core": None}
    root = None
    report["passed"] = False
    try:
        with tempfile.TemporaryDirectory(prefix="recall-opendal-minio-") as temporary:
            root = Path(temporary)
            if args.minio:
                minio = args.minio.resolve()
                report["minio_origin"] = "externally supplied binary; source provenance not verified by this script"
            else:
                source = json.loads(subprocess.check_output(["go", "mod", "download", "-json", MINIO_MODULE], text=True))
                assert source["Sum"] == MINIO_SUM and source["Origin"]["Hash"] == MINIO_COMMIT
                report.update(minio_source_commit=MINIO_COMMIT, minio_module_sum=MINIO_SUM,
                              go_version=subprocess.check_output(["go", "version"], text=True).strip())
                minio = root / "minio"
                subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-o", str(minio), "."],
                               cwd=source["Dir"], env=dict(os.environ, CGO_ENABLED="0"), check=True)
            report["minio_binary_sha256"] = hashlib.sha256(minio.read_bytes()).hexdigest()
            report["provider_sha256"] = hashlib.sha256(args.provider.read_bytes()).hexdigest()
            if args.baseline:
                report["baseline_sha256"] = hashlib.sha256(args.baseline.read_bytes()).hexdigest()
            if args.core:
                report["core_sha256"] = hashlib.sha256(args.core.read_bytes()).hexdigest()
                report["core_version"] = subprocess.check_output([str(args.core.resolve()), "--version"], text=True).strip()
            access, secret = "test" + secrets.token_hex(8), secrets.token_hex(24)
            port = free_port()
            endpoint = f"http://127.0.0.1:{port}"
            env = dict(os.environ, MINIO_ROOT_USER=access, MINIO_ROOT_PASSWORD=secret,
                       MINIO_BROWSER="off", MINIO_UPDATE="off", MINIO_REGION_NAME="us-east-1")
            with (root / "server.log").open("w") as log:
                process = subprocess.Popen([str(minio), "--quiet", "server", "--address",
                    f"127.0.0.1:{port}", "--console-address", f"127.0.0.1:{free_port()}", str(root / "data")],
                    env=env, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 60
                    while True:
                        try:
                            with urllib.request.urlopen(endpoint + "/minio/health/ready", timeout=1):
                                break
                        except (OSError, urllib.error.URLError):
                            assert process.poll() is None and time.monotonic() < deadline, "MinIO failed to start"
                            time.sleep(0.1)
                    bucket = "recall-isolated-fixture"
                    # Readiness may precede storage initialization in a fresh MinIO.
                    # Retry only setup's 503; provider requests retain their own result.
                    deadline = time.monotonic() + 60
                    while True:
                        try:
                            signed_request(endpoint, "PUT", f"/{bucket}", b"", access, secret)
                            break
                        except urllib.error.HTTPError as error:
                            if error.code != 503 or time.monotonic() >= deadline:
                                raise
                            time.sleep(0.2)
                    for label, binary in [("baseline", args.baseline), ("candidate", args.provider)]:
                        if binary:
                            results, _, _ = check_provider(binary.resolve(), root, endpoint, bucket, access, secret, label)
                            report["tests"][label] = results
                            print(json.dumps({"build": label, "checks": results}), flush=True)
                    if args.core:
                        report["core"] = check_core(args.core.resolve(), args.provider.resolve(), root,
                            endpoint, bucket, access, secret)
                    assert all(report["tests"]["candidate"].values()), report["tests"]["candidate"]
                    if args.baseline:
                        assert not all(report["tests"]["baseline"].values()), "baseline did not reproduce regression"
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)
                    report["server_reaped"] = process.poll() is not None
        report["passed"] = True
    finally:
        report["temporary_environment_removed"] = root is not None and not root.exists()
        if args.receipt:
            args.receipt.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report), flush=True)



if __name__ == "__main__":
    main()
