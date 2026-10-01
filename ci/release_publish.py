#!/usr/bin/env python3
"""Publish the immutable keyman release flag to Forgejo."""
from __future__ import annotations

import argparse
import datetime
import json
import os
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
OWNER_REPO = "HOMESERVERSLTD/keyman"

RELEASE_RETENTION = 20
RELEASE_PAGE_LIMIT = 50
FLAG_NAME = "release.flag"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
RELEASE_TAG = re.compile(r"^sha-([0-9a-fA-F]{40})$")
UNIX_TIMESTAMP = re.compile(r"^[0-9]+$")


class ReleaseError(RuntimeError):
    """A failure that is safe to expose in the CI receipt."""


class RetentionFailure(ReleaseError):
    """A retention failure with a truthful partial-operation receipt."""

    def __init__(self, message: str, receipt: dict[str, Any]):
        super().__init__(message)
        self.receipt = receipt


def fail(message: str) -> NoReturn:
    raise ReleaseError(message)


def ssl_context() -> ssl.SSLContext:
    cafile = os.environ.get("SSL_CERT_FILE")
    return ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()


def request_url(path_or_url: str) -> str:
    """Allow only the fixed Forgejo HTTPS host for every request and redirect."""
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


def decode_json(raw: bytes, description: str) -> Any:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{description} returned invalid JSON")
        raise AssertionError("unreachable") from exc


def flagged_at() -> str:
    raw = os.environ.get("CI_COMMIT_TIMESTAMP", "")
    if not UNIX_TIMESTAMP.fullmatch(raw):
        fail("CI_COMMIT_TIMESTAMP must be a required UNIX timestamp")
    try:
        value = datetime.datetime.fromtimestamp(int(raw), datetime.timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        fail(f"CI_COMMIT_TIMESTAMP is out of range: {exc}")
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def flag_bytes(source_sha: str, pipeline_url: str) -> bytes:
    if not FULL_SHA.fullmatch(source_sha):
        fail("CI_COMMIT_SHA must be exactly 40 lowercase hexadecimal characters")
    if not pipeline_url:
        fail("CI_PIPELINE_URL is required")
    payload = {
        "schema": "estate.release-flag.v1",
        "component": "keyman",
        "source_sha": source_sha,
        "flagged_at": flagged_at(),
        "pipeline_url": pipeline_url,
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def release_tag(source_sha: str) -> str:
    if not FULL_SHA.fullmatch(source_sha):
        fail("CI_COMMIT_SHA must be exactly 40 lowercase hexadecimal characters")
    return f"sha-{source_sha}"


def release_tag_url(source_sha: str) -> str:
    tag = release_tag(source_sha)
    return f"/repos/{OWNER_REPO}/releases/tags/{urllib.parse.quote(tag, safe='')}"


def release_page_url(source_sha: str) -> str:
    tag = release_tag(source_sha)
    return f"{WEB}/{OWNER_REPO}/releases/tag/{urllib.parse.quote(tag, safe='')}"


def read_release(source_sha: str, token: str) -> dict[str, Any] | None:
    status, raw = request("GET", release_tag_url(source_sha), token)
    if status == 404:
        return None
    if status != 200:
        fail(f"release lookup returned HTTP {status}")
    value = decode_json(raw, "release lookup")
    if not isinstance(value, dict):
        fail("release lookup returned a non-object")
    return value


def validate_identity(release: dict[str, Any], source_sha: str) -> int:
    if (
        release.get("tag_name") != release_tag(source_sha)
        or release.get("name") != f"keyman {source_sha[:8]}"
        or release.get("target_commitish") != source_sha
        or ("target_commit" in release and release["target_commit"] != source_sha)
    ):
        fail("release identity conflicts with CI_COMMIT_SHA")
    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        fail("release response omitted its numeric id")
    return release_id


def validate_assets(release: dict[str, Any], expected_names: set[str]) -> dict[str, dict[str, Any]]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        fail("release response has no asset list")
    by_name: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            fail("release contains a malformed asset")
        name = asset["name"]
        if name in by_name:
            fail("release contains duplicate asset names")
        by_name[name] = asset
    if set(by_name) != expected_names:
        fail("release assets do not exactly match the release.flag contract")
    return by_name


def download_asset(asset: dict[str, Any], token: str) -> bytes:
    download_url = asset.get("browser_download_url")
    if not isinstance(download_url, str):
        fail("release.flag asset response omitted its browser download URL")
    status, raw = request(
        "GET",
        download_url,
        token,
        accept="application/octet-stream",
    )
    if status != 200:
        fail(f"release.flag download returned HTTP {status}")
    return raw


def validate_existing(release: dict[str, Any], source_sha: str, token: str, expected: bytes) -> None:
    validate_identity(release, source_sha)
    assets = validate_assets(release, {FLAG_NAME})
    if download_asset(assets[FLAG_NAME], token) != expected:
        fail("immutable release.flag conflict; refusing overwrite")


def multipart_flag(content: bytes) -> tuple[bytes, str]:
    boundary = "keyman-release-" + secrets.token_hex(16)
    header = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="attachment"; '
        f'filename="{FLAG_NAME}"\r\nContent-Type: application/json; charset=utf-8\r\n\r\n'
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
        f"/repos/{OWNER_REPO}/releases",
        token,
        body=payload,
        content_type="application/json",
    )
    if status == 409:
        raced = read_release(source_sha, token)
        if raced is None:
            fail("release create race did not produce a readable release")
        return raced, True
    if status != 201:
        fail(f"release creation returned HTTP {status}")
    value = decode_json(raw, "release creation")
    if not isinstance(value, dict):
        fail("release creation returned a non-object")
    validate_identity(value, source_sha)
    validate_assets(value, set())
    return value, False


def publish(source_sha: str, token: str, expected: bytes) -> tuple[str, str]:
    existing = read_release(source_sha, token)
    if existing is not None:
        validate_existing(existing, source_sha, token, expected)
        return "no-op", release_page_url(source_sha)

    release, raced = create_release(source_sha, token)
    if raced:
        validate_existing(release, source_sha, token, expected)
        return "no-op", release_page_url(source_sha)
    release_id = validate_identity(release, source_sha)
    if release.get("assets") != []:
        validate_assets(release, set())

    body, content_type = multipart_flag(expected)
    status, _ = request(
        "POST",
        f"/repos/{OWNER_REPO}/releases/{release_id}/assets?"
        + urllib.parse.urlencode({"name": FLAG_NAME}),
        token,
        body=body,
        content_type=content_type,
    )
    if status != 201:
        fail(f"release.flag upload returned HTTP {status}")

    reread = read_release(source_sha, token)
    if reread is None:
        fail("release reread returned HTTP 404")
    validate_existing(reread, source_sha, token, expected)
    return "published", release_page_url(source_sha)


def _repo_path() -> str:
    return "/repos/" + "/".join(
        urllib.parse.quote(part, safe="") for part in OWNER_REPO.split("/")
    )


def list_releases(token: str) -> list[dict[str, Any]]:
    base = _repo_path() + "/releases"
    releases: list[dict[str, Any]] = []
    seen_pages: set[str] = set()
    seen_ids: set[int] = set()
    page = 1
    while True:
        query = urllib.parse.urlencode({"page": page, "limit": RELEASE_PAGE_LIMIT})
        status, raw = request("GET", f"{base}?{query}", token)
        if status != 200:
            fail(f"release listing page {page} returned HTTP {status}")
        values = decode_json(raw, f"release listing page {page}")
        if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
            fail(f"release listing page {page} returned a malformed list")
        if len(values) < RELEASE_PAGE_LIMIT:
            releases.extend(values)
            return releases
        fingerprint = json.dumps(values, sort_keys=True, separators=(",", ":"))
        if fingerprint in seen_pages:
            fail(f"release listing page {page} repeated a previous full page")
        seen_pages.add(fingerprint)
        page_ids = {
            item["id"] for item in values
            if isinstance(item.get("id"), int) and not isinstance(item.get("id"), bool)
        }
        if page_ids and page_ids.issubset(seen_ids):
            fail(f"release listing page {page} made no progress")
        seen_ids.update(page_ids)
        releases.extend(values)
        page += 1


def _eligible_release(release: dict[str, Any]) -> tuple[datetime.datetime, int] | None:
    tag = release.get("tag_name")
    target = release.get("target_commitish")
    if release.get("draft") is not False or not isinstance(tag, str):
        return None
    match = RELEASE_TAG.fullmatch(tag)
    if match is None or target != match.group(1):
        return None
    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        fail("eligible release omitted its numeric id")
    created = release.get("created_at")
    if not isinstance(created, str):
        fail(f"eligible release {release_id} omitted created_at")
    try:
        created_at = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError:
        fail(f"eligible release {release_id} has invalid created_at")
    if created_at.tzinfo is None:
        fail(f"eligible release {release_id} has timezone-free created_at")
    return created_at.astimezone(datetime.timezone.utc), release_id


def _release_order(release: dict[str, Any]) -> tuple[datetime.datetime, int]:
    order = _eligible_release(release)
    if order is None:
        fail("internal retention ordering error")
    return order


def _verify_tag_absent(tag: str, token: str) -> bool:
    path = _repo_path() + "/git/refs/tags/" + urllib.parse.quote(tag, safe="")
    status, _ = request("GET", path, token)
    if status == 404:
        return True
    if status == 200:
        return False
    fail(f"tag ref {tag} cannot be verified: GET returned HTTP {status}")


def retention_plan(
    token: str, protected_id: int | None = None, *, protected_tag: str | None = None
) -> dict[str, Any]:
    eligible = [item for item in list_releases(token) if _eligible_release(item) is not None]
    if protected_tag is not None:
        matching = [item for item in eligible if item.get("tag_name") == protected_tag]
        if matching:
            protected_id = matching[0]["id"]
    eligible.sort(key=_release_order, reverse=True)
    kept = eligible[:RELEASE_RETENTION]
    protected = next((item for item in eligible if item.get("id") == protected_id), None)
    retained = kept + ([protected] if protected is not None and protected not in kept else [])
    overflow = [item for item in eligible[RELEASE_RETENTION:] if item.get("id") != protected_id]
    return {
        "eligible_count": len(eligible),
        "boundary": {
            "retention": RELEASE_RETENTION,
            "rank_20_id": kept[-1].get("id") if len(kept) == RELEASE_RETENTION else None,
            "rank_21_id": eligible[RELEASE_RETENTION].get("id") if len(eligible) > RELEASE_RETENTION else None,
        },
        "kept_ids": [item["id"] for item in retained],
        "protected_id": protected_id,
        "delete_candidates": overflow,
    }


def apply_retention(token: str, protected_id: int) -> dict[str, Any]:
    plan = retention_plan(token, protected_id)
    deleted_ids: list[int] = []
    deleted_tags: list[str] = []
    remaining_tag_refs: list[str] = []
    base = _repo_path()
    attempted_id: int | None = None
    attempted_tag: str | None = None
    phase = "start"

    def receipt() -> dict[str, Any]:
        return {
            "mode": "partial",
            "kept_count": len(plan["kept_ids"]),
            "deleted_ids": deleted_ids,
            "deleted_tags": deleted_tags,
            "remaining_tag_refs": remaining_tag_refs,
            "attempted": {"id": attempted_id, "tag": attempted_tag, "phase": phase},
            "boundary": plan["boundary"],
        }

    try:
        for release in plan["delete_candidates"]:
            release_id = release["id"]
            tag = release["tag_name"]
            attempted_id = release_id
            attempted_tag = tag
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
            status, _ = request(
                "DELETE", f"{base}/tags/{urllib.parse.quote(tag, safe='')}", token
            )
            if status not in (204, 404):
                fail(f"tag deletion for {tag} returned HTTP {status}")

            phase = "tag_verify"
            if _verify_tag_absent(tag, token):
                deleted_tags.append(tag)
            else:
                remaining_tag_refs.append(tag)
    except ReleaseError as exc:
        raise RetentionFailure(str(exc), receipt()) from exc

    return {
        "mode": "applied",
        "kept_count": len(plan["kept_ids"]),
        "kept_ids": plan["kept_ids"],
        "deleted_ids": deleted_ids,
        "deleted_tags": deleted_tags,
        "remaining_tag_refs": remaining_tag_refs,
        "boundary": plan["boundary"],
    }


def dry_run_retention(token: str, protected_tag: str | None = None) -> dict[str, Any]:
    plan = retention_plan(token, protected_tag=protected_tag)
    return {
        "mode": "dry-run",
        "kept_count": len(plan["kept_ids"]),
        "kept_ids": plan["kept_ids"],
        "would_delete_ids": [item["id"] for item in plan["delete_candidates"]],
        "would_delete_tags": [item["tag_name"] for item in plan["delete_candidates"]],
        "boundary": plan["boundary"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Publish keyman release.flag and retain newest releases")
    parser.add_argument("--dry-run", action="store_true", help="GET-only retention plan (no publishing or deletion)")
    args = parser.parse_args()
    token = os.environ.get("FORGEJO_TOKEN", "").strip()
    if not token:
        print(json.dumps({"status": "error", "error": "FORGEJO_TOKEN is required"}, separators=(",", ":")))
        return 1
    try:
        if args.dry_run:
            protected_tag = None
            source_sha = os.environ.get("CI_COMMIT_SHA", "")
            if FULL_SHA.fullmatch(source_sha):
                protected_tag = release_tag(source_sha)
            result = dry_run_retention(token, protected_tag)
            print(json.dumps({"status": "ok", "repo": OWNER_REPO, "retention": result}, separators=(",", ":")))
            return 0
        source_sha = os.environ.get("CI_COMMIT_SHA", "")
        expected = flag_bytes(source_sha, os.environ.get("CI_PIPELINE_URL", ""))
        status, url = publish(source_sha, token, expected)
        retention = None
        if os.environ.get("CI_COMMIT_BRANCH") == "main":
            release = read_release(source_sha, token)
            if release is None:
                fail("published release disappeared before retention")
            protected_id = validate_identity(release, source_sha)
            validate_existing(release, source_sha, token, expected)
            retention = apply_retention(token, protected_id)
    except ReleaseError as exc:
        error: dict[str, Any] = {"status": "error", "error": str(exc)}
        if isinstance(exc, RetentionFailure):
            error["retention"] = exc.receipt
        print(json.dumps(error, separators=(",", ":")))
        return 1
    print(
        json.dumps(
            {
                "status": status,
                "tag": release_tag(source_sha),
                "name": f"keyman {source_sha[:8]}",
                "assets": [FLAG_NAME],
                "release_url": url,
                "retention": retention,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
