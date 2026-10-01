#!/usr/bin/env python3
"""Publish Keyman's immutable Rust binary release, checksum, and flag."""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, NoReturn

API = "https://git.home.arpa/api/v1"
WEB = "https://git.home.arpa"
REPO = "HOMESERVERSLTD/keyman"
RELEASE_FLAG_SEAT_URL = (
    "https://git.home.arpa/HOMESERVERSLTD/caduceus/raw/branch/main/"
    "schema/estate.release-flag.v1.json"
)
RELEASE_FLAG_SCHEMA = "estate.release-flag.v1"
BINARY_NAME = "keyman-x86_64"
SIDECAR_NAME = BINARY_NAME + ".sha256"
FLAG_NAME = "release.flag"
ASSET_NAMES = {BINARY_NAME, SIDECAR_NAME, FLAG_NAME}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
RELEASE_TAG = re.compile(r"^sha-([0-9a-f]{40})$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
RETENTION_COUNT = 20
RELEASE_PAGE_LIMIT = 50
DOWNLOAD_PREFIX = f"/{REPO}/releases/download/"
RELEASE_PREFIX = f"/{REPO}/releases/"


class ReleaseError(RuntimeError):
    """A publication failure safe to summarize in CI output."""


class RetentionFailure(ReleaseError):
    """A retention failure carrying the operations already observed."""

    def __init__(self, message: str, receipt: dict[str, Any]):
        super().__init__(message)
        self.receipt = receipt


def fail(message: str) -> NoReturn:
    raise ReleaseError(message)


def ssl_context() -> ssl.SSLContext:
    cafile = os.environ.get("SSL_CERT_FILE")
    return ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()


def request_url(path_or_url: str) -> str:
    """Restrict API calls, assets, and redirects to Forgejo over HTTPS."""
    parsed = urllib.parse.urlsplit(path_or_url)
    if parsed.scheme:
        if (
            parsed.scheme != "https"
            or parsed.hostname != "git.home.arpa"
            or parsed.netloc != "git.home.arpa"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.port not in (None, 443)
        ):
            fail("refusing URL outside the fixed Forgejo HTTPS host")
        return path_or_url
    if not path_or_url.startswith("/"):
        fail("Forgejo API path must be absolute")
    return API + path_or_url


class FixedHostRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        request_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request(
    method: str,
    path_or_url: str,
    token: str,
    *,
    body: bytes | None = None,
    content_type: str | None = None,
    accept: str = "application/json",
) -> tuple[int, bytes]:
    headers = {"Authorization": f"token {token}", "Accept": accept}
    if content_type:
        headers["Content-Type"] = content_type
    url = request_url(path_or_url)
    opener = urllib.request.build_opener(
        FixedHostRedirects,
        urllib.request.HTTPSHandler(context=ssl_context()),
    )
    try:
        with opener.open(
            urllib.request.Request(url, data=body, headers=headers, method=method),
            timeout=120,
        ) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code, b""
    except (urllib.error.URLError, OSError) as exc:
        detail = exc.reason if isinstance(exc, urllib.error.URLError) else type(exc).__name__
        fail(f"transport failure for {method} {path_or_url}: {detail}")
    raise AssertionError("unreachable")


def request_json(
    method: str,
    path: str,
    token: str,
    *,
    body: bytes | None = None,
    content_type: str | None = None,
    expected_statuses: tuple[int, ...] = (200,),
) -> Any:
    status, raw = request(
        method, path, token, body=body, content_type=content_type
    )
    if status not in expected_statuses:
        fail(f"{method} {path} returned HTTP {status}")
    try:
        return json.loads(raw) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"{method} {path} returned invalid JSON") from exc


def request_bytes(path_or_url: str, token: str) -> bytes:
    status, raw = request(
        "GET", path_or_url, token, accept="application/octet-stream"
    )
    if status != 200:
        fail(f"GET {path_or_url} returned HTTP {status}")
    return raw


def _repo_path() -> str:
    return "/repos/" + "/".join(
        urllib.parse.quote(part, safe="") for part in REPO.split("/")
    )


def release_tag(source_sha: str) -> str:
    if not isinstance(source_sha, str) or not FULL_SHA.fullmatch(source_sha):
        fail("source SHA must be exactly 40 lowercase hexadecimal characters")
    return "sha-" + source_sha


def release_tag_url(source_sha: str) -> str:
    tag = release_tag(source_sha)
    return _repo_path() + "/releases/tags/" + urllib.parse.quote(tag, safe="")


def release_page_url(release: dict[str, Any], source_sha: str) -> str:
    tag = release_tag(source_sha)
    value = release.get("html_url")
    if value is None:
        value = WEB + RELEASE_PREFIX + "tag/" + urllib.parse.quote(tag, safe="")
    parsed = urllib.parse.urlsplit(value)
    expected_path = RELEASE_PREFIX + "tag/" + urllib.parse.quote(tag, safe="")
    if (
        parsed.scheme != "https"
        or parsed.hostname != "git.home.arpa"
        or parsed.netloc != "git.home.arpa"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.path != expected_path
    ):
        fail("release URL does not match the fixed Forgejo tag path")
    return value


def read_release(source_sha: str, token: str) -> dict[str, Any] | None:
    path = release_tag_url(source_sha)
    status, raw = request("GET", path, token)
    if status == 404:
        return None
    if status != 200:
        fail(f"release lookup returned HTTP {status}")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("release lookup returned invalid JSON") from exc
    if not isinstance(value, dict):
        fail("release lookup returned a non-object")
    return value


def read_release_id(release_id: int, token: str) -> dict[str, Any]:
    value = request_json("GET", f"{_repo_path()}/releases/{release_id}", token)
    if not isinstance(value, dict):
        fail("release lookup by id returned a non-object")
    return value


def validate_release_identity(release: dict[str, Any], source_sha: str) -> int:
    if not isinstance(release, dict):
        fail("Forgejo release response is not an object")
    if (
        release.get("tag_name") != release_tag(source_sha)
        or release.get("name") != f"keyman {source_sha[:8]}"
        or release.get("target_commitish") != source_sha
        or release.get("draft") is not False
        or release.get("prerelease") is not False
    ):
        fail("release identity conflicts with source SHA")
    target_commit = release.get("target_commit")
    if target_commit is not None and target_commit != source_sha:
        fail("release target commit conflicts with source SHA")
    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        fail("release response omitted its numeric id")
    return release_id


def validate_assets(
    release: dict[str, Any], *, allow_partial: bool = False
) -> dict[str, dict[str, Any]]:
    raw_assets = release.get("assets")
    if not isinstance(raw_assets, list):
        fail("release response has no asset list")
    by_name: dict[str, dict[str, Any]] = {}
    for asset in raw_assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            fail("release contains a malformed asset")
        name = asset["name"]
        if name in by_name:
            fail("release contains duplicate asset names")
        by_name[name] = asset
    names = set(by_name)
    if allow_partial:
        if not names.issubset(ASSET_NAMES):
            fail("release contains assets outside the immutable Keyman contract")
    elif names != ASSET_NAMES:
        fail("release assets do not exactly match the Keyman contract")
    return by_name


def expected_asset_url(asset: dict[str, Any], source_sha: str) -> str:
    name = asset.get("name")
    value = asset.get("browser_download_url")
    if not isinstance(name, str) or name not in ASSET_NAMES or not isinstance(value, str):
        fail("release asset response omitted a valid name or download URL")
    tag = release_tag(source_sha)
    expected_path = (
        DOWNLOAD_PREFIX
        + urllib.parse.quote(tag, safe="")
        + "/"
        + urllib.parse.quote(name, safe="")
    )
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "git.home.arpa"
        or parsed.netloc != "git.home.arpa"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.path != expected_path
    ):
        fail("asset download URL does not match the fixed Forgejo tag and asset path")
    return value


def download_asset(asset: dict[str, Any], source_sha: str, token: str) -> bytes:
    return request_bytes(expected_asset_url(asset, source_sha), token)


def _json_type_matches(value: Any, type_name: str) -> bool:
    if type_name == "null":
        return value is None
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def load_release_flag_seat(token: str) -> dict[str, Any]:
    raw = request_bytes(RELEASE_FLAG_SEAT_URL, token)
    try:
        seat = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("release flag schema seat is not valid JSON") from exc
    if not isinstance(seat, dict) or seat.get("schema") != RELEASE_FLAG_SCHEMA:
        fail("release flag schema seat has a foreign schema")
    required = seat.get("required")
    fields = seat.get("fields")
    if (
        not isinstance(required, list)
        or not required
        or any(not isinstance(field, str) or not field for field in required)
        or not isinstance(fields, dict)
    ):
        fail("release flag schema seat has invalid required fields or field declarations")
    return seat


def validate_release_flag(
    flag: Any,
    seat: dict[str, Any],
    source_sha: str,
    binary_digest: str,
) -> dict[str, Any]:
    if not isinstance(flag, dict) or flag.get("schema") != RELEASE_FLAG_SCHEMA:
        fail("release.flag has a foreign schema or is not an object")
    required = seat["required"]
    fields = seat["fields"]
    for field in required:
        if field not in flag or flag[field] is None or flag[field] == "":
            fail(f"release.flag required field {field} is absent or empty")
    for field, value in flag.items():
        rule = fields.get(field)
        if not isinstance(rule, dict):
            continue
        declared_type = rule.get("type")
        if declared_type is not None:
            allowed_types = declared_type if isinstance(declared_type, list) else [declared_type]
            if not isinstance(allowed_types, list) or not any(
                isinstance(item, str) and _json_type_matches(value, item)
                for item in allowed_types
            ):
                fail(f"release.flag field {field} has the wrong schema type")
        if "const" in rule and value != rule["const"]:
            fail(f"release.flag field {field} conflicts with its schema constant")
        enum = rule.get("enum")
        if isinstance(enum, list) and value not in enum:
            fail(f"release.flag field {field} is outside its schema enum")
        pattern = rule.get("pattern")
        if pattern is not None:
            if not isinstance(pattern, str):
                fail(f"release flag schema pattern for {field} is invalid")
            try:
                if not isinstance(value, str) or re.search(pattern, value) is None:
                    fail(f"release.flag field {field} does not match its schema pattern")
            except re.error as exc:
                raise ReleaseError(f"release flag schema pattern for {field} is invalid") from exc
    if flag.get("component") != "keyman":
        fail("release.flag component conflicts with keyman")
    if flag.get("source_sha") != source_sha:
        fail("release.flag source SHA conflicts with its release tag")
    if flag.get("sha256") != binary_digest or not DIGEST.fullmatch(str(flag.get("sha256", ""))):
        fail("release.flag binary digest conflicts with the published binary")
    if not isinstance(flag.get("flagged_at"), str) or not isinstance(flag.get("pipeline_url"), str):
        fail("release.flag timestamp or pipeline URL is invalid")
    return flag


def canonical_release_flag(
    source_sha: str,
    binary_digest: str,
    pipeline_url: str,
    seat: dict[str, Any],
) -> bytes:
    if not pipeline_url:
        fail("CI_PIPELINE_URL is required")
    flag = {
        "schema": RELEASE_FLAG_SCHEMA,
        "component": "keyman",
        "source_sha": source_sha,
        "sha256": binary_digest,
        "flagged_at": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "pipeline_url": pipeline_url,
    }
    validate_release_flag(flag, seat, source_sha, binary_digest)
    return (json.dumps(flag, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def validate_existing_asset(
    name: str,
    asset: dict[str, Any],
    source_sha: str,
    token: str,
    seat: dict[str, Any],
    binary: bytes,
    sidecar: bytes,
    binary_digest: str,
) -> None:
    downloaded = download_asset(asset, source_sha, token)
    if name == BINARY_NAME:
        if downloaded != binary:
            fail("immutable release binary conflict; refusing overwrite")
        return
    if name == SIDECAR_NAME:
        if downloaded != sidecar:
            fail("immutable release checksum conflict; refusing overwrite")
        return
    try:
        flag = json.loads(downloaded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("existing release.flag is not valid JSON") from exc
    validate_release_flag(flag, seat, source_sha, binary_digest)


def _multipart_asset(content: bytes, name: str, content_type: str) -> tuple[bytes, str]:
    boundary = "keyman-release-" + secrets.token_hex(16)
    header = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="attachment"; '
        f'filename="{name}"\r\nContent-Type: {content_type}\r\n\r\n'
    ).encode("ascii")
    trailer = f"\r\n--{boundary}--\r\n".encode("ascii")
    return header + content + trailer, f"multipart/form-data; boundary={boundary}"


def create_release(source_sha: str, token: str) -> tuple[dict[str, Any], bool]:
    payload = json.dumps(
        {
            "tag_name": release_tag(source_sha),
            "target_commitish": source_sha,
            "name": f"keyman {source_sha[:8]}",
            "body": "",
            "draft": False,
            "prerelease": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    status, raw = request(
        "POST",
        _repo_path() + "/releases",
        token,
        body=payload,
        content_type="application/json",
    )
    if status == 409:
        raced = read_release(source_sha, token)
        if raced is None:
            fail("release create race did not produce a readable release")
        return raced, False
    if status != 201:
        fail(f"release creation returned HTTP {status}")
    try:
        release = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseError("release creation returned invalid JSON") from exc
    if not isinstance(release, dict):
        fail("release creation returned a non-object")
    validate_release_identity(release, source_sha)
    validate_assets(release, allow_partial=True)
    return release, True


def _verify_present_assets(
    assets: dict[str, dict[str, Any]],
    source_sha: str,
    token: str,
    seat: dict[str, Any],
    binary: bytes,
    sidecar: bytes,
    binary_digest: str,
) -> None:
    for name, asset in assets.items():
        validate_existing_asset(
            name,
            asset,
            source_sha,
            token,
            seat,
            binary,
            sidecar,
            binary_digest,
        )


def upload_missing_asset(
    release: dict[str, Any],
    name: str,
    content: bytes,
    content_type: str,
    source_sha: str,
    token: str,
    seat: dict[str, Any],
    binary: bytes,
    sidecar: bytes,
    binary_digest: str,
) -> dict[str, Any]:
    release_id = validate_release_identity(release, source_sha)
    body, multipart_type = _multipart_asset(content, name, content_type)
    status, _ = request(
        "POST",
        f"{_repo_path()}/releases/{release_id}/assets?"
        + urllib.parse.urlencode({"name": name}),
        token,
        body=body,
        content_type=multipart_type,
    )
    # A lost response or concurrent uploader is safe only if the exact asset
    # can be read back and verified; this lane never replaces an existing one.
    reread = read_release_id(release_id, token)
    validate_release_identity(reread, source_sha)
    assets = validate_assets(reread, allow_partial=True)
    if name not in assets:
        fail(f"{name} upload returned HTTP {status} and the asset is absent")
    validate_existing_asset(
        name,
        assets[name],
        source_sha,
        token,
        seat,
        binary,
        sidecar,
        binary_digest,
    )
    return reread


def publish_release(
    source_sha: str,
    token: str,
    seat: dict[str, Any],
    binary: bytes,
    sidecar: bytes,
    flag_bytes: bytes,
    binary_digest: str,
) -> tuple[str, dict[str, Any], str]:
    release = read_release(source_sha, token)
    created = False
    changed = False
    if release is None:
        release, created = create_release(source_sha, token)
        changed = created

    release_id = validate_release_identity(release, source_sha)
    assets = validate_assets(release, allow_partial=True)
    _verify_present_assets(
        assets, source_sha, token, seat, binary, sidecar, binary_digest
    )

    # Historical flag-only releases are immutable. Do not retrofit binary
    # assets into one; an interrupted new upload can resume only after at least
    # one matching binary/checksum asset proves the new contract was started.
    if FLAG_NAME in assets and not {BINARY_NAME, SIDECAR_NAME}.issubset(assets):
        fail("immutable flag-only release conflict; refusing to modify historical release")
    if not created and not assets:
        fail("existing empty release conflict; refusing to modify it")

    upload_order = (
        (BINARY_NAME, binary, "application/octet-stream"),
        (SIDECAR_NAME, sidecar, "text/plain"),
        (FLAG_NAME, flag_bytes, "application/json"),
    )
    for name, content, content_type in upload_order:
        if name in assets:
            continue
        release = upload_missing_asset(
            release,
            name,
            content,
            content_type,
            source_sha,
            token,
            seat,
            binary,
            sidecar,
            binary_digest,
        )
        assets = validate_assets(release, allow_partial=True)
        changed = True

    final_release = read_release_id(release_id, token)
    validate_release_identity(final_release, source_sha)
    final_assets = validate_assets(final_release)
    _verify_present_assets(
        final_assets, source_sha, token, seat, binary, sidecar, binary_digest
    )
    return ("published" if changed else "no-op"), final_release, release_page_url(
        final_release, source_sha
    )


def list_releases(token: str) -> list[dict[str, Any]]:
    base = _repo_path() + "/releases"
    releases: list[dict[str, Any]] = []
    seen_pages: set[str] = set()
    seen_ids: set[int] = set()
    page = 1
    while True:
        path = base + "?" + urllib.parse.urlencode(
            {"page": page, "limit": RELEASE_PAGE_LIMIT}
        )
        batch = request_json("GET", path, token)
        if not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch):
            fail(f"release listing page {page} returned a malformed list")
        if len(batch) < RELEASE_PAGE_LIMIT:
            releases.extend(batch)
            return releases
        fingerprint = json.dumps(batch, sort_keys=True, separators=(",", ":"))
        if fingerprint in seen_pages:
            fail(f"release listing page {page} repeated a previous full page")
        seen_pages.add(fingerprint)
        page_ids = {
            item["id"]
            for item in batch
            if isinstance(item.get("id"), int) and not isinstance(item.get("id"), bool)
        }
        if page_ids and page_ids.issubset(seen_ids):
            fail(f"release listing page {page} made no progress")
        seen_ids.update(page_ids)
        releases.extend(batch)
        page += 1


def eligible_release_order(
    release: dict[str, Any],
) -> tuple[datetime.datetime, int] | None:
    tag = release.get("tag_name")
    target = release.get("target_commitish")
    if (
        release.get("draft") is not False
        or release.get("prerelease") is True
        or not isinstance(tag, str)
    ):
        return None
    match = RELEASE_TAG.fullmatch(tag)
    if match is None or target != match.group(1):
        return None
    target_commit = release.get("target_commit")
    if target_commit is not None and target_commit != match.group(1):
        return None
    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        fail("eligible release omitted its numeric id")
    created = release.get("created_at")
    if not isinstance(created, str):
        fail(f"eligible release {release_id} omitted created_at")
    try:
        created_at = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseError(f"eligible release {release_id} has invalid created_at") from exc
    if created_at.tzinfo is None:
        fail(f"eligible release {release_id} has timezone-free created_at")
    return created_at.astimezone(datetime.timezone.utc), release_id


def apply_retention(token: str, protected_release_id: int) -> dict[str, Any]:
    deleted_ids: list[int] = []
    deleted_tags: list[str] = []
    remaining_tag_refs: list[str] = []
    plan: dict[str, Any] = {"kept_ids": [], "delete_candidates": []}
    phase = "list"
    attempted_id: int | None = None
    attempted_tag: str | None = None

    def receipt() -> dict[str, Any]:
        return {
            "retained_ids": plan["kept_ids"],
            "deleted_ids": deleted_ids,
            "deleted_tags": deleted_tags,
            "remaining_tag_refs": remaining_tag_refs,
            "attempted": {"id": attempted_id, "tag": attempted_tag, "phase": phase},
        }

    try:
        ordered: list[tuple[tuple[datetime.datetime, int], dict[str, Any]]] = []
        for item in list_releases(token):
            order = eligible_release_order(item)
            if order is not None:
                ordered.append((order, item))
        ordered.sort(key=lambda entry: entry[0], reverse=True)
        eligible = [item for _, item in ordered]
        if not any(item.get("id") == protected_release_id for item in eligible):
            fail("published release is absent from the eligible retention set")
        retained = eligible[:RETENTION_COUNT]
        if all(item.get("id") != protected_release_id for item in retained):
            protected = next(
                item for item in eligible if item.get("id") == protected_release_id
            )
            retained.append(protected)
        retained_ids = {item["id"] for item in retained}
        plan["kept_ids"] = [item["id"] for item in retained]
        plan["delete_candidates"] = [
            item for item in eligible if item.get("id") not in retained_ids
        ]

        base = _repo_path()
        for release in plan["delete_candidates"]:
            release_id = release["id"]
            tag = release["tag_name"]
            attempted_id, attempted_tag = release_id, tag
            phase = "release_delete"
            status, _ = request("DELETE", f"{base}/releases/{release_id}", token)
            if status not in (200, 204):
                fail(f"release deletion for id {release_id} returned HTTP {status}")
            phase = "release_verify"
            status, _ = request("GET", f"{base}/releases/{release_id}", token)
            if status != 404:
                fail(f"release deletion verification for id {release_id} returned HTTP {status}")
            deleted_ids.append(release_id)

            phase = "tag_delete"
            tag_path = base + "/tags/" + urllib.parse.quote(tag, safe="")
            status, _ = request("DELETE", tag_path, token)
            if status not in (200, 204, 404):
                fail(f"tag deletion for {tag} returned HTTP {status}")
            phase = "tag_verify"
            ref_path = base + "/git/refs/tags/" + urllib.parse.quote(tag, safe="")
            status, _ = request("GET", ref_path, token)
            if status == 404:
                deleted_tags.append(tag)
            elif status == 200:
                remaining_tag_refs.append(tag)
            else:
                fail(f"tag ref {tag} verification returned HTTP {status}")

        phase = "release_readback"
        final_releases = list_releases(token)
        final_eligible = [
            item
            for item in final_releases
            if eligible_release_order(item) is not None
        ]
        surviving_tags = sorted(item["tag_name"] for item in final_eligible)
        if remaining_tag_refs:
            raise RetentionFailure(
                "one or more pruned Git tag refs remain",
                {
                    **receipt(),
                    "surviving_tags": surviving_tags,
                },
            )
        return {
            "retained_count": len(retained),
            "retained_tags": [item["tag_name"] for item in retained],
            "surviving_tags": surviving_tags,
            "deleted_ids": deleted_ids,
            "deleted_tags": deleted_tags,
        }
    except RetentionFailure:
        raise
    except ReleaseError as exc:
        raise RetentionFailure(str(exc), receipt()) from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--sidecar", required=True)
    parser.add_argument("--pipeline-url", required=True)
    args = parser.parse_args()

    token = os.environ.get("FORGEJO_TOKEN", "").strip()
    if not token:
        print(json.dumps({"status": "error", "error": "FORGEJO_TOKEN is required"}, separators=(",", ":")))
        return 1

    try:
        source_sha = args.source_sha
        release_tag(source_sha)
        if not args.pipeline_url:
            fail("CI_PIPELINE_URL is required")
        if Path(args.binary).name != BINARY_NAME or Path(args.sidecar).name != SIDECAR_NAME:
            fail("binary and sidecar names do not match the Keyman release contract")
        binary_path = Path(args.binary)
        sidecar_path = Path(args.sidecar)
        if not binary_path.is_file() or not sidecar_path.is_file():
            fail("binary or checksum sidecar does not exist")
        binary = binary_path.read_bytes()
        if not binary:
            fail("Rust binary is empty")
        binary_digest = hashlib.sha256(binary).hexdigest()
        expected_sidecar = f"{binary_digest}  {BINARY_NAME}\n".encode("ascii")
        sidecar = sidecar_path.read_bytes()
        if sidecar != expected_sidecar:
            fail("checksum sidecar is not the exact sha256 record for the binary")

        seat = load_release_flag_seat(token)
        flag_bytes = canonical_release_flag(
            source_sha, binary_digest, args.pipeline_url, seat
        )
        status, release, url = publish_release(
            source_sha,
            token,
            seat,
            binary,
            sidecar,
            flag_bytes,
            binary_digest,
        )
        release_id = validate_release_identity(release, source_sha)
        retention = apply_retention(token, release_id)
    except RetentionFailure as exc:
        print(
            json.dumps(
                {"status": "error", "error": str(exc), "retention": exc.receipt},
                separators=(",", ":"),
            )
        )
        return 1
    except ReleaseError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":")))
        return 1

    print(
        json.dumps(
            {
                "status": status,
                "tag": release_tag(args.source_sha),
                "commit": args.source_sha,
                "assets": [BINARY_NAME, SIDECAR_NAME, FLAG_NAME],
                "sha256": binary_digest,
                "release_url": url,
                "retention": retention,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
