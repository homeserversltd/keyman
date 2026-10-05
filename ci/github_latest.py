#!/usr/bin/env python3
"""Mirror keyman's current Forgejo Release to the sole GitHub `latest` release."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, NoReturn

FORGEJO_API = "https://git.home.arpa/api/v1"
GITHUB_API = "https://api.github.com"
GITHUB_UPLOADS = "https://uploads.github.com"
FORGEJO_GIT = "https://git.home.arpa/HOMESERVERSLTD/keyman.git"
OWNER_REPO = "HOMESERVERSLTD/keyman"
FORGEJO_PUSH_MIRRORS_SYNC_PATH = f"/repos/{OWNER_REPO}/push_mirrors-sync"
SOURCE_TAG_PREFIX = "sha-"
LATEST_TAG = "latest"
FLAG_NAME = "release.flag"
BINARY_NAME = "keyman-x86_64"
SIDECAR_NAME = BINARY_NAME + ".sha256"
ASSET_NAMES = {BINARY_NAME, SIDECAR_NAME, FLAG_NAME}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
FORGEJO_HOSTS = frozenset({"git.home.arpa"})
GITHUB_API_HOSTS = frozenset({"api.github.com"})
GITHUB_DOWNLOAD_HOSTS = frozenset({"github.com"})
GITHUB_DOWNLOAD_REDIRECT_HOSTS = frozenset({"release-assets.githubusercontent.com"})
GITHUB_UPLOAD_HOSTS = frozenset({"uploads.github.com"})


class SyncError(RuntimeError):
    """A safe-to-report refusal without request headers or credential values."""


class SupersededError(SyncError):
    """CI source is no longer Forgejo main; no later write is permitted."""

    def __init__(self, main_sha: str, boundary: str):
        self.main_sha = main_sha
        self.boundary = boundary
        super().__init__(f"Forgejo main no longer matches CI_COMMIT_SHA before {boundary}")


def fail(message: str) -> NoReturn:
    raise SyncError(message)


def _validate_url(url: str, allowed_hosts: frozenset[str]) -> str:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hosts
        or parsed.netloc not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or parsed.fragment
    ):
        fail("refusing URL outside the fixed HTTPS host allowlist")
    return url


class FixedHostRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: frozenset[str]):
        super().__init__()
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_url(newurl, self.allowed_hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class ReleaseAssetRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _validate_url(newurl, GITHUB_DOWNLOAD_REDIRECT_HOSTS)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def tls_context() -> ssl.SSLContext:
    ca_path = os.environ.get("SSL_CERT_FILE", "")
    if not ca_path or not Path(ca_path).is_file() or Path(ca_path).stat().st_size == 0:
        fail("SSL_CERT_FILE must name the installed non-empty house CA bundle")

    # The complete Kether bundle already has public roots and the house CA;
    # avoid platform-first loading, whose duplicate-certificate selection order
    # is ambiguous.
    return ssl.create_default_context(cafile=ca_path)


def request(
    method: str,
    url_or_path: str,
    token: str,
    *,
    service: str,
    body: bytes | None = None,
    content_type: str | None = None,
    accept: str = "application/json",
) -> tuple[int, bytes]:
    if service == "forgejo":
        base = FORGEJO_API
        hosts = FORGEJO_HOSTS
        if not token:
            fail("FORGEJO_TOKEN is required for Forgejo requests")
        headers = {"Authorization": f"token {token}", "Accept": accept}
    elif service == "github":
        base = GITHUB_API
        hosts = GITHUB_API_HOSTS
        headers = {
            "Accept": "application/vnd.github+json" if accept == "application/json" else accept,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "keyman-github-latest-mirror",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
    elif service == "github-download":
        base = ""
        hosts = GITHUB_DOWNLOAD_HOSTS
        headers = {"Accept": accept, "User-Agent": "keyman-github-latest-mirror"}
    elif service == "github-uploads":
        base = GITHUB_UPLOADS
        hosts = GITHUB_UPLOAD_HOSTS
        if not token:
            fail("GITHUB_TOKEN is required for GitHub writes")
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "keyman-github-latest-mirror",
        }
    else:
        fail("internal request service is invalid")

    if url_or_path.startswith("/"):
        if service.startswith("github"):
            parts = urllib.parse.urlsplit(url_or_path).path.split("/")
            if (
                len(parts) < 5
                or parts[0] != ""
                or parts[1] != "repos"
                or not repository_path_segments_match(url_or_path, 2)
            ):
                fail("refusing GitHub API path outside the fixed repository")
        url = base + url_or_path
    else:
        url = url_or_path
    _validate_url(url, hosts)
    if content_type:
        headers["Content-Type"] = content_type
    redirects = (
        ReleaseAssetRedirects()
        if service == "github-download"
        else FixedHostRedirects(hosts)
    )
    opener = urllib.request.build_opener(
        redirects, urllib.request.HTTPSHandler(context=tls_context())
    )
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with opener.open(req, timeout=45) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        # Status is useful; the body may contain reflected request data.
        try:
            exc.read()
        except OSError:
            pass
        return exc.code, b""
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", None)
        reason_name = type(reason).__name__ if reason is not None else type(exc).__name__
        fail(f"{service} {method} transport failure ({reason_name})")
    raise AssertionError("unreachable")


def decode_json(raw: bytes, label: str) -> Any:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError(f"{label} returned invalid JSON") from exc


def json_body(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def checked_asset_name(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        fail("release contains an invalid asset name")
    return value


def repository_full_name_matches(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    parts = value.split("/")
    owner, repo = OWNER_REPO.split("/")
    return (
        len(parts) == 2
        and parts[0].casefold() == owner.casefold()
        and parts[1].casefold() == repo.casefold()
    )


def repository_path_segments_match(path: str, owner_index: int) -> bool:
    parts = urllib.parse.urlsplit(path).path.split("/")
    owner, repo = OWNER_REPO.split("/")
    return (
        len(parts) > owner_index + 1
        and parts[owner_index].casefold() == owner.casefold()
        and parts[owner_index + 1].casefold() == repo.casefold()
    )


def validate_release_repository(release: dict[str, Any], service: str) -> None:
    if "full_name" in release and not repository_full_name_matches(release["full_name"]):
        fail(f"{service} release belongs to a different repository")


def github_upload_url(release: dict[str, Any], release_id: int) -> str:
    raw_url = release.get("upload_url")
    if not isinstance(raw_url, str):
        fail(f"GitHub release {release_id} omitted its upload URL")
    template = "{?name,label}"
    if template in raw_url:
        if not raw_url.endswith(template) or raw_url.count(template) != 1:
            fail(f"GitHub release {release_id} has an invalid upload URL template")
        url = raw_url[: -len(template)]
    else:
        if "{" in raw_url or "}" in raw_url:
            fail(f"GitHub release {release_id} has an invalid upload URL template")
        url = raw_url
    _validate_url(url, GITHUB_UPLOAD_HOSTS)
    parsed = urllib.parse.urlsplit(url)
    parts = parsed.path.split("/")
    if (
        parsed.query
        or parsed.fragment
        or len(parts) != 7
        or parts[0] != ""
        or parts[1] != "repos"
        or not repository_path_segments_match(parsed.path, 2)
        or parts[4:] != ["releases", str(release_id), "assets"]
    ):
        fail(f"GitHub release {release_id} upload URL points to a different release")
    return url


def _download_forgejo_asset(asset: dict[str, Any], tag: str, token: str) -> bytes:
    name = checked_asset_name(asset.get("name"))
    url = asset.get("browser_download_url")
    if not isinstance(url, str):
        fail(f"Forgejo asset {name} omitted its download URL")
    _validate_url(url, FORGEJO_HOSTS)
    parsed = urllib.parse.urlsplit(url)
    parts = parsed.path.split("/")
    expected_suffix = ["releases", "download", tag, urllib.parse.quote(name, safe="")]
    if (
        not repository_path_segments_match(parsed.path, 1)
        or len(parts) != 7
        or parts[0] != ""
        or parts[3:] != expected_suffix
        or parsed.query
        or parsed.fragment
    ):
        fail(f"Forgejo asset {name} download URL is outside its exact release")
    status, raw = request(
        "GET", url, token, service="forgejo", accept="application/octet-stream"
    )
    if status != 200:
        fail(f"Forgejo asset {name} download returned HTTP {status}")
    declared_size = asset.get("size")
    if isinstance(declared_size, int) and not isinstance(declared_size, bool) and declared_size != len(raw):
        fail(f"Forgejo asset {name} size differs from its release metadata")
    return raw


def _validate_forgejo_asset_sidecars(payloads: dict[str, bytes]) -> None:
    sidecar_suffix = ".sha256"
    sidecar_names = {name for name in payloads if name.endswith(sidecar_suffix)}
    asset_names = set(payloads) - sidecar_names

    for name in sorted(asset_names - {FLAG_NAME}):
        if name + sidecar_suffix not in sidecar_names:
            fail(f"Forgejo asset {name} has no SHA256 sidecar")

    for sidecar_name in sorted(sidecar_names):
        asset_name = sidecar_name[: -len(sidecar_suffix)]
        if not asset_name or asset_name not in asset_names:
            fail(f"Forgejo SHA256 sidecar {sidecar_name} has no matching asset")
        try:
            line = payloads[sidecar_name].decode("ascii")
        except UnicodeDecodeError:
            fail(f"Forgejo SHA256 sidecar {sidecar_name} is not ASCII")
        if not line.endswith("\n"):
            fail(f"Forgejo SHA256 sidecar {sidecar_name} must end with exactly one newline")
        line = line[:-1]
        if "\n" in line or "\r" in line:
            fail(f"Forgejo SHA256 sidecar {sidecar_name} must contain exactly one line ending in a newline")
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None or match.group(2) != asset_name:
            fail(f"Forgejo SHA256 sidecar {sidecar_name} has an invalid digest+filename line")
        actual_digest = hashlib.sha256(payloads[asset_name]).hexdigest()
        if match.group(1) != actual_digest:
            fail(f"Forgejo SHA256 sidecar {sidecar_name} digest does not match its asset")


def load_forgejo_release(source_sha: str, token: str) -> tuple[dict[str, Any] | None, dict[str, bytes]]:
    tag = SOURCE_TAG_PREFIX + source_sha
    path = f"/repos/{OWNER_REPO}/releases/tags/{urllib.parse.quote(tag, safe='')}"
    status, raw = request("GET", path, token, service="forgejo")
    if status == 404:
        return None, {}
    if status != 200:
        fail(f"Forgejo release lookup returned HTTP {status}")
    release = decode_json(raw, "Forgejo release lookup")
    if not isinstance(release, dict):
        fail("Forgejo release lookup returned a non-object")
    validate_release_repository(release, "Forgejo")
    if (
        release.get("tag_name") != tag
        or release.get("target_commitish") != source_sha
        or ("target_commit" in release and release["target_commit"] != source_sha)
    ):
        fail("Forgejo release identity conflicts with CI_COMMIT_SHA")
    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        fail("Forgejo release omitted its numeric id")
    assets = release.get("assets")
    if not isinstance(assets, list):
        fail("Forgejo release has no asset list")
    by_name: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            fail("Forgejo release contains a malformed asset")
        name = checked_asset_name(asset.get("name"))
        if name in by_name:
            fail("Forgejo release contains duplicate asset names")
        by_name[name] = asset
    if set(by_name) != ASSET_NAMES:
        fail("Forgejo release assets do not exactly match the Keyman contract")
    if FLAG_NAME not in by_name:
        fail("Forgejo release is missing release.flag")
    payloads = {
        name: _download_forgejo_asset(asset, tag, token)
        for name, asset in sorted(by_name.items())
    }
    _validate_forgejo_asset_sidecars(payloads)
    try:
        flag = json.loads(payloads[FLAG_NAME])
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SyncError("Forgejo release.flag is invalid JSON") from exc
    if (
        not isinstance(flag, dict)
        or flag.get("schema") != "estate.release-flag.v1"
        or flag.get("component") != "keyman"
        or flag.get("source_sha") != source_sha
        or not isinstance(flag.get("source_sha"), str)
        or not FULL_SHA.fullmatch(flag["source_sha"])
        or not isinstance(flag.get("sha256"), str)
        or flag["sha256"] != hashlib.sha256(payloads[BINARY_NAME]).hexdigest()
    ):
        fail("Forgejo release.flag source_sha, digest, or identity is invalid")
    return release, payloads


def read_forgejo_ref(token: str) -> dict[str, Any] | None:
    path = f"/repos/{OWNER_REPO}/git/refs/tags/{LATEST_TAG}"
    status, raw = request("GET", path, token, service="forgejo")
    if status == 404:
        return None
    if status != 200:
        fail(f"Forgejo latest tag lookup returned HTTP {status}")
    value = decode_json(raw, "Forgejo latest tag lookup")
    if isinstance(value, list):
        matches = [item for item in value if isinstance(item, dict) and item.get("ref") == f"refs/tags/{LATEST_TAG}"]
        if len(matches) > 1:
            fail("Forgejo returned multiple refs for refs/tags/latest")
        ref = matches[0] if matches else None
    elif isinstance(value, dict):
        ref = value if value.get("ref") == f"refs/tags/{LATEST_TAG}" else None
    else:
        fail("Forgejo latest tag lookup returned a malformed ref")
    if ref is None:
        return None
    obj = ref.get("object")
    if (
        not isinstance(obj, dict)
        or not isinstance(obj.get("sha"), str)
        or not FULL_SHA.fullmatch(obj["sha"])
        or obj.get("type") not in {"commit", "tag"}
    ):
        fail("Forgejo latest tag ref has an invalid object")
    return ref


def read_forgejo_main_sha(token: str) -> str:
    path = f"/repos/{OWNER_REPO}/git/refs/heads/main"
    status, raw = request("GET", path, token, service="forgejo")
    if status != 200:
        fail(f"Forgejo main ref lookup returned HTTP {status}")
    value = decode_json(raw, "Forgejo main ref lookup")
    if isinstance(value, list):
        matches = [
            item
            for item in value
            if isinstance(item, dict) and item.get("ref") == "refs/heads/main"
        ]
        if len(matches) != 1:
            fail("Forgejo returned a missing or repeated main ref")
        ref = matches[0]
    elif isinstance(value, dict) and value.get("ref") == "refs/heads/main":
        ref = value
    else:
        fail("Forgejo returned a malformed main ref")
    obj = ref.get("object")
    if (
        not isinstance(obj, dict)
        or obj.get("type") != "commit"
        or not isinstance(obj.get("sha"), str)
        or not FULL_SHA.fullmatch(obj["sha"])
    ):
        fail("Forgejo main ref has an invalid commit SHA")
    return obj["sha"]


def require_forgejo_main_is_source(source_sha: str, token: str, boundary: str) -> str:
    main_sha = read_forgejo_main_sha(token)
    if main_sha != source_sha:
        raise SupersededError(main_sha, boundary)
    return main_sha


def forgejo_ref_points_to_sha(ref: dict[str, Any] | None, source_sha: str) -> bool:
    return (
        ref is not None
        and ref["object"].get("type") == "commit"
        and ref["object"].get("sha") == source_sha
    )


def resolve_forgejo_tag_commit(ref: dict[str, Any] | None, token: str) -> str | None:
    if ref is None:
        return None
    obj = ref["object"]
    sha = obj["sha"]
    kind = obj["type"]
    seen: set[str] = set()
    for _ in range(9):
        if sha in seen:
            fail("Forgejo latest tag has a tag-object cycle")
        seen.add(sha)
        if kind == "commit":
            return sha
        status, raw = request("GET", f"/repos/{OWNER_REPO}/git/tags/{sha}", token, service="forgejo")
        if status != 200:
            fail(f"Forgejo annotated latest tag lookup returned HTTP {status}")
        tag_object = decode_json(raw, "Forgejo annotated latest tag lookup")
        nested = tag_object.get("object") if isinstance(tag_object, dict) else None
        if not isinstance(nested, dict) or nested.get("type") not in {"commit", "tag"}:
            fail("Forgejo annotated latest tag has an invalid target")
        sha = nested.get("sha")
        kind = nested["type"]
        if not isinstance(sha, str) or not FULL_SHA.fullmatch(sha):
            fail("Forgejo annotated latest tag target SHA is invalid")
    fail("Forgejo latest tag exceeds the annotated-tag resolution bound")


def github_api_path(path: str) -> str:
    return f"/repos/{OWNER_REPO}/{path.lstrip('/')}"


def list_github_releases(token: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen_pages: set[str] = set()
    seen_ids: set[int] = set()
    page = 1
    while True:
        query = urllib.parse.urlencode({"per_page": 100, "page": page})
        status, raw = request(
            "GET", github_api_path(f"releases?{query}"), token, service="github"
        )
        if status != 200:
            fail(f"GitHub release listing page {page} returned HTTP {status}")
        values = decode_json(raw, f"GitHub release listing page {page}")
        if not isinstance(values, list) or any(not isinstance(item, dict) for item in values):
            fail(f"GitHub release listing page {page} is malformed")
        for item in values:
            validate_release_repository(item, "GitHub")
            release_id = item.get("id")
            if not isinstance(release_id, int) or isinstance(release_id, bool):
                fail("GitHub release omitted its numeric id")
            if release_id in seen_ids:
                fail("GitHub release listing repeated an id")
            seen_ids.add(release_id)
        if len(values) < 100:
            result.extend(values)
            return result
        fingerprint = json.dumps(values, sort_keys=True, separators=(",", ":"))
        if fingerprint in seen_pages:
            fail(f"GitHub release listing page {page} repeated")
        seen_pages.add(fingerprint)
        result.extend(values)
        page += 1


def release_inventory_conflicts(releases: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not releases or (len(releases) == 1 and releases[0].get("tag_name") == LATEST_TAG):
        return []
    return [
        {"id": item["id"], "tag_name": item.get("tag_name")}
        for item in releases
    ]


def require_single_latest_release(releases: list[dict[str, Any]]) -> dict[str, Any] | None:
    conflicts = release_inventory_conflicts(releases)
    if conflicts:
        fail("GitHub release inventory conflicts with the single-latest-release invariant")
    return releases[0] if releases else None


def github_asset_map(release: dict[str, Any]) -> dict[str, dict[str, Any]]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        fail("GitHub latest release has no asset list")
    result: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict):
            fail("GitHub latest release contains a malformed asset")
        name = checked_asset_name(asset.get("name"))
        if name in result:
            fail("GitHub latest release contains duplicate asset names")
        asset_id = asset.get("id")
        if not isinstance(asset_id, int) or isinstance(asset_id, bool):
            fail(f"GitHub asset {name} omitted its numeric id")
        result[name] = asset
    return result


def download_github_asset(asset: dict[str, Any]) -> bytes:
    name = checked_asset_name(asset.get("name"))
    url = asset.get("browser_download_url")
    if not isinstance(url, str):
        fail(f"GitHub asset {name} omitted its browser download URL")
    _validate_url(url, GITHUB_DOWNLOAD_HOSTS)
    parsed = urllib.parse.urlsplit(url)
    parts = parsed.path.split("/")
    expected_suffix = [
        "releases",
        "download",
        LATEST_TAG,
        urllib.parse.quote(name, safe=""),
    ]
    if (
        not repository_path_segments_match(parsed.path, 1)
        or len(parts) != 7
        or parts[0] != ""
        or parts[3:] != expected_suffix
        or parsed.query
        or parsed.fragment
    ):
        fail(f"GitHub asset {name} download URL is outside the exact latest release asset")
    status, raw = request(
        "GET", url, "", service="github-download", accept="application/octet-stream"
    )
    if status != 200:
        fail(f"GitHub asset {name} download returned HTTP {status}")
    declared_size = asset.get("size")
    if isinstance(declared_size, int) and not isinstance(declared_size, bool) and declared_size != len(raw):
        fail(f"GitHub asset {name} size differs from its metadata")
    return raw


def github_assets_match(
    release: dict[str, Any] | None, expected: dict[str, bytes]
) -> tuple[bool, list[str], dict[str, bytes]]:
    if release is None:
        return False, [], {}
    current = github_asset_map(release)
    expected_names = set(expected)
    differences: list[str] = []
    if set(current) != expected_names:
        differences.extend(sorted((set(current) - expected_names) | (expected_names - set(current))))
    actual_payloads: dict[str, bytes] = {}
    for name in sorted(current):
        actual_payloads[name] = download_github_asset(current[name])
        if name in expected and actual_payloads[name] != expected[name]:
            differences.append(name)
    return not differences, sorted(set(differences)), actual_payloads


def read_github_main_sha() -> str:
    status, raw = request(
        "GET", github_api_path("git/ref/heads/main"), "", service="github"
    )
    if status != 200:
        fail(f"GitHub main ref lookup returned HTTP {status}")
    ref = decode_json(raw, "GitHub main ref lookup")
    obj = ref.get("object") if isinstance(ref, dict) else None
    if (
        not isinstance(ref, dict)
        or ref.get("ref") != "refs/heads/main"
        or not isinstance(obj, dict)
        or obj.get("type") != "commit"
        or not isinstance(obj.get("sha"), str)
        or not FULL_SHA.fullmatch(obj["sha"])
    ):
        fail("GitHub returned a malformed main ref")
    return obj["sha"]


def read_github_ref() -> dict[str, Any] | None:
    path = github_api_path("git/ref/tags/latest")
    status, raw = request("GET", path, "", service="github")
    if status == 404:
        return None
    if status != 200:
        fail(f"GitHub latest tag lookup returned HTTP {status}")
    ref = decode_json(raw, "GitHub latest tag lookup")
    if not isinstance(ref, dict) or ref.get("ref") != "refs/tags/latest":
        fail("GitHub returned a malformed latest tag ref")
    obj = ref.get("object")
    if not isinstance(obj, dict) or not isinstance(obj.get("sha"), str) or not FULL_SHA.fullmatch(obj["sha"]):
        fail("GitHub latest tag ref has an invalid object")
    if obj.get("type") not in {"commit", "tag"}:
        fail("GitHub latest tag ref points to an unsupported object type")
    return ref


def resolve_github_tag_commit(ref: dict[str, Any] | None) -> str | None:
    if ref is None:
        return None
    obj = ref["object"]
    sha = obj["sha"]
    kind = obj["type"]
    seen: set[str] = set()
    for _ in range(9):
        if sha in seen:
            fail("GitHub latest tag has a tag-object cycle")
        seen.add(sha)
        if kind == "commit":
            return sha
        status, raw = request("GET", github_api_path(f"git/tags/{sha}"), "", service="github")
        if status != 200:
            fail(f"GitHub annotated latest tag lookup returned HTTP {status}")
        tag_object = decode_json(raw, "GitHub annotated latest tag lookup")
        nested = tag_object.get("object") if isinstance(tag_object, dict) else None
        if not isinstance(nested, dict) or nested.get("type") not in {"commit", "tag"}:
            fail("GitHub annotated latest tag has an invalid target")
        sha = nested.get("sha")
        kind = nested["type"]
        if not isinstance(sha, str) or not FULL_SHA.fullmatch(sha):
            fail("GitHub annotated latest tag target SHA is invalid")
    fail("GitHub latest tag exceeds the annotated-tag resolution bound")


def github_ref_points_to_sha(ref: dict[str, Any] | None, source_sha: str) -> bool:
    return (
        ref is not None
        and ref["object"].get("type") == "commit"
        and ref["object"].get("sha") == source_sha
    )


def wait_for_github_mirror(source_sha: str) -> tuple[str, dict[str, Any] | None]:
    for attempt in range(37):
        main_sha = read_github_main_sha()
        ref = read_github_ref()
        if main_sha == source_sha and github_ref_points_to_sha(ref, source_sha):
            return main_sha, ref
        if attempt < 36:
            time.sleep(5)
    fail("GitHub main and latest tag did not mirror CI_COMMIT_SHA within 180 seconds")


def push_forgejo_tag(source_sha: str, expected_object_sha: str | None, token: str) -> None:
    cafile = os.environ.get("SSL_CERT_FILE", "")
    if not cafile or not Path(cafile).is_file() or Path(cafile).stat().st_size == 0:
        fail("SSL_CERT_FILE must name the installed CA bundle before tag push")
    with tempfile.TemporaryDirectory(prefix="keyman-forgejo-askpass-") as temp_dir:
        askpass = Path(temp_dir) / "askpass"
        askpass.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  *Username*) printf '%s\\n' 'oauth2' ;;\n"
            "  *Password*) printf '%s\\n' \"$FORGEJO_TOKEN\" ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n",
            encoding="utf-8",
        )
        askpass.chmod(0o700)
        env = os.environ.copy()
        env.update(
            {
                "FORGEJO_TOKEN": token,
                "GIT_ASKPASS": str(askpass),
                "GIT_ASKPASS_REQUIRE": "force",
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TRACE": "0",
                "GIT_TRACE_CURL": "0",
                "GIT_CURL_VERBOSE": "0",
                "GIT_TRACE_PACKET": "0",
            }
        )
        expected = expected_object_sha or ""
        command = [
            "git",
            "-c",
            "credential.helper=",
            "-c",
            f"http.sslCAInfo={cafile}",
            "push",
            f"--force-with-lease=refs/tags/latest:{expected}",
            "--",
            FORGEJO_GIT,
            f"{source_sha}:refs/tags/latest",
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                env=env,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise SyncError(f"Forgejo latest tag push could not complete ({type(exc).__name__})") from exc
        if completed.returncode != 0:
            fail(f"Forgejo latest tag push failed (exit status {completed.returncode})")


def ensure_forgejo_latest_tag(source_sha: str, token: str) -> dict[str, Any]:
    before = read_forgejo_ref(token)
    old_object_sha = before["object"]["sha"] if before is not None else None
    changed = not forgejo_ref_points_to_sha(before, source_sha)
    if changed:
        require_forgejo_main_is_source(source_sha, token, "latest tag push")
        push_forgejo_tag(source_sha, old_object_sha, token)
    after = read_forgejo_ref(token)
    if after is None or not forgejo_ref_points_to_sha(after, source_sha):
        fail("Forgejo latest tag readback does not point directly to CI_COMMIT_SHA")
    return {
        "old_object_sha": old_object_sha,
        "new_sha": source_sha,
        "action": "force-move" if changed else "keep",
        "readback_object_sha": after["object"]["sha"],
    }


def sync_forgejo_push_mirrors(token: str) -> int:
    status, _ = request(
        "POST", FORGEJO_PUSH_MIRRORS_SYNC_PATH, token, service="forgejo", body=b""
    )
    print(
        json.dumps(
            {
                "step": "github-latest-keyman",
                "operation": "push_mirrors-sync",
                "http_status": status,
            },
            separators=(",", ":"),
        )
    )
    if not 200 <= status < 300:
        fail(
            "github-latest-keyman refusal: Forgejo push_mirrors-sync returned "
            f"HTTP {status}"
        )
    return status


def read_github_release(release_id: int, token: str) -> dict[str, Any]:
    status, raw = request(
        "GET", github_api_path(f"releases/{release_id}"), token, service="github"
    )
    if status != 200:
        fail(f"GitHub release {release_id} readback returned HTTP {status}")
    release = decode_json(raw, f"GitHub release {release_id} readback")
    if not isinstance(release, dict) or release.get("id") != release_id:
        fail(f"GitHub release {release_id} readback has the wrong identity")
    validate_release_repository(release, "GitHub")
    return release


def delete_release_assets(release_id: int, release: dict[str, Any], token: str) -> None:
    assets = github_asset_map(release)
    for name, asset in sorted(assets.items()):
        status, _ = request(
            "DELETE",
            github_api_path(f"releases/assets/{asset['id']}"),
            token,
            service="github",
        )
        if status not in (204, 404):
            fail(f"GitHub asset deletion for {name} returned HTTP {status}")
        reread = read_github_release(release_id, token)
        if name in github_asset_map(reread):
            fail(f"GitHub asset deletion for {name} was not verified")
    reread = read_github_release(release_id, token)
    if reread.get("tag_name") != LATEST_TAG or github_asset_map(reread):
        fail("GitHub latest release still has assets after replacement preparation")


def create_github_release(source_sha: str, token: str) -> dict[str, Any]:
    payload = {
        "tag_name": LATEST_TAG,
        "target_commitish": source_sha,
        "name": "keyman latest",
        "body": "",
        "draft": False,
        "prerelease": False,
    }
    status, raw = request(
        "POST",
        github_api_path("releases"),
        token,
        service="github",
        body=json_body(payload),
        content_type="application/json",
    )
    if status != 201:
        fail(f"GitHub latest release creation returned HTTP {status}")
    release = decode_json(raw, "GitHub latest release creation")
    if not isinstance(release, dict) or release.get("tag_name") != LATEST_TAG:
        fail("GitHub created a release with the wrong tag")
    validate_release_repository(release, "GitHub")
    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        fail("GitHub latest release creation omitted its numeric id")
    return read_github_release(release_id, token)


def update_public_release(
    release: dict[str, Any], source_sha: str, token: str
) -> dict[str, Any]:
    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        fail("GitHub latest release omitted its numeric id")
    if (
        release.get("target_commitish") == source_sha
        and release.get("draft") is False
        and release.get("prerelease") is False
    ):
        return release
    status, raw = request(
        "PATCH",
        github_api_path(f"releases/{release_id}"),
        token,
        service="github",
        body=json_body(
            {"target_commitish": source_sha, "draft": False, "prerelease": False}
        ),
        content_type="application/json",
    )
    if status != 200:
        fail(f"GitHub latest release metadata update returned HTTP {status}")
    updated = decode_json(raw, "GitHub latest release metadata update")
    if not isinstance(updated, dict) or updated.get("tag_name") != LATEST_TAG:
        fail("GitHub latest release identity changed during metadata update")
    validate_release_repository(updated, "GitHub")
    reread = read_github_release(release_id, token)
    if (
        reread.get("target_commitish") != source_sha
        or reread.get("draft") is not False
        or reread.get("prerelease") is not False
    ):
        fail("GitHub latest release metadata update was not verified")
    return reread


def upload_assets(release: dict[str, Any], expected: dict[str, bytes], token: str) -> None:
    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        fail("GitHub latest release omitted its numeric id")
    validate_release_repository(release, "GitHub")
    upload_url = github_upload_url(release, release_id)
    for name, content in sorted(expected.items()):
        url = f"{upload_url}?name={urllib.parse.quote(name, safe='')}"
        status, raw = request(
            "POST",
            url,
            token,
            service="github-uploads",
            body=content,
            content_type="application/octet-stream",
        )
        if status != 201:
            fail(f"GitHub asset upload for {name} returned HTTP {status}")
        uploaded = decode_json(raw, f"GitHub asset upload {name}")
        if not isinstance(uploaded, dict) or uploaded.get("name") != name:
            fail(f"GitHub asset upload for {name} returned the wrong asset")
        reread = read_github_release(release_id, token)
        asset = github_asset_map(reread).get(name)
        if asset is None or download_github_asset(asset) != content:
            fail(f"GitHub asset upload for {name} was not verified")


def verify_github_release(
    source_sha: str, expected: dict[str, bytes], token: str
) -> tuple[dict[str, Any], str, dict[str, Any], dict[str, bytes]]:
    main_sha, ref = wait_for_github_mirror(source_sha)
    releases = list_github_releases(token)
    release = require_single_latest_release(releases)
    if release is None:
        fail("GitHub latest release is absent after publication")
    if release.get("target_commitish") != source_sha:
        fail("GitHub latest release target does not match CI_COMMIT_SHA")
    if release.get("draft") is not False or release.get("prerelease") is not False:
        fail("GitHub latest release is not a public stable release")
    matches, differences, actual_assets = github_assets_match(release, expected)
    if not matches:
        fail("GitHub latest release assets differ from Forgejo: " + ", ".join(differences))
    if ref is None or not github_ref_points_to_sha(ref, source_sha):
        fail("GitHub latest tag readback does not point directly to CI_COMMIT_SHA")
    return release, main_sha, ref, actual_assets


def asset_summary(payloads: dict[str, bytes]) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for name, content in sorted(payloads.items())
    ]


def exact_state_noop(
    source_sha: str,
    expected: dict[str, bytes],
    forgejo_token: str,
    latest: dict[str, Any] | None,
) -> dict[str, Any] | None:
    if (
        latest is None
        or latest.get("tag_name") != LATEST_TAG
        or latest.get("target_commitish") != source_sha
        or latest.get("draft") is not False
        or latest.get("prerelease") is not False
    ):
        return None
    forgejo_ref = read_forgejo_ref(forgejo_token)
    if not forgejo_ref_points_to_sha(forgejo_ref, source_sha):
        return None
    github_main = read_github_main_sha()
    if github_main != source_sha:
        return None
    github_ref = read_github_ref()
    if not github_ref_points_to_sha(github_ref, source_sha):
        return None
    assets_match, _differences, actual_assets = github_assets_match(latest, expected)
    if not assets_match:
        return None
    return {
        "status": "no-op",
        "repo": OWNER_REPO,
        "source_sha": source_sha,
        "forgejo": {
            "tag": f"refs/tags/{LATEST_TAG}",
            "action": "keep",
            "object_sha": forgejo_ref["object"]["sha"],
        },
        "github": {
            "main_sha": github_main,
            "mirror_tag": {
                "ref": f"refs/tags/{LATEST_TAG}",
                "object_sha": github_ref["object"]["sha"],
                "target_commit_sha": source_sha,
            },
            "release_id": latest["id"],
            "target_commitish": source_sha,
            "draft": False,
            "prerelease": False,
            "assets": asset_summary(actual_assets),
        },
    }


def get_plan(
    source_sha: str,
    release: dict[str, Any] | None,
    expected: dict[str, bytes],
    forgejo_token: str,
    github_token: str,
) -> dict[str, Any]:
    forgejo_ref = read_forgejo_ref(forgejo_token)
    forgejo_target = resolve_forgejo_tag_commit(forgejo_ref, forgejo_token)
    forgejo_main_sha = read_forgejo_main_sha(forgejo_token)
    forgejo_main_matches = forgejo_main_sha == source_sha
    main_sha = read_github_main_sha()
    github_ref = read_github_ref()
    github_target = resolve_github_tag_commit(github_ref)
    releases = list_github_releases(github_token)
    latest_candidates = [item for item in releases if item.get("tag_name") == LATEST_TAG]
    latest = latest_candidates[0] if len(latest_candidates) == 1 else None
    assets_match, differing_assets, actual_assets = github_assets_match(latest, expected)
    conflicts = release_inventory_conflicts(releases)
    mirror_ready = main_sha == source_sha and github_ref_points_to_sha(github_ref, source_sha)
    if conflicts:
        planned_release_actions = ["blocked-conflict"]
        planned_asset_action = "blocked-conflict"
    else:
        if latest is None:
            planned_release_actions = ["create"]
        else:
            planned_release_actions = []
            if latest.get("target_commitish") != source_sha:
                planned_release_actions.append("refresh-metadata")
            if latest.get("draft") is not False or latest.get("prerelease") is not False:
                planned_release_actions.append("promote")
            if not planned_release_actions:
                planned_release_actions.append("keep")
        planned_asset_action = (
            "no-op" if latest is not None and assets_match else "replace"
        )

    if conflicts:
        release_action = "blocked-conflict"
        asset_action = "blocked-conflict"
    elif not forgejo_main_matches:
        release_action = "blocked-stale-source"
        asset_action = "blocked-stale-source"
    elif not mirror_ready:
        release_action = "wait-for-mirror"
        asset_action = "wait-for-mirror"
    else:
        release_action = (
            planned_release_actions[0]
            if len(planned_release_actions) == 1
            else "update"
        )
        asset_action = planned_asset_action
    return {
        "status": "plan",
        "mode": "GET-only",
        "repo": OWNER_REPO,
        "source_sha": source_sha,
        "target_commitish": source_sha,
        "forgejo": {
            "main_sha": forgejo_main_sha,
            "main_matches_source": forgejo_main_matches,
            "write_guard": "ready" if forgejo_main_matches else "blocked-stale-source",
            "release": (
                None
                if release is None
                else {
                    "release_id": release["id"],
                    "tag": release["tag_name"],
                    "target_commitish": source_sha,
                }
            ),
            "latest_tag": {
                "ref": f"refs/tags/{LATEST_TAG}",
                "exists": forgejo_ref is not None,
                "old_object_sha": forgejo_ref["object"]["sha"] if forgejo_ref is not None else None,
                "old_target_commit_sha": forgejo_target,
                "new_sha": source_sha,
                "target_commitish": source_sha,
                "action": (
                    "blocked-stale-source"
                    if not forgejo_main_matches
                    else "keep"
                    if forgejo_ref_points_to_sha(forgejo_ref, source_sha)
                    else "force-move"
                ),
                "assets": asset_summary(expected),
            },
            "push_mirrors_sync": {
                "method": "POST",
                "path": FORGEJO_PUSH_MIRRORS_SYNC_PATH,
                "body": "empty",
                "action": "pending",
            },
        },
        "github": {
            "main_sha": main_sha,
            "mirror_tag": {
                "ref": f"refs/tags/{LATEST_TAG}",
                "exists": github_ref is not None,
                "object_sha": github_ref["object"]["sha"] if github_ref is not None else None,
                "target_commit_sha": github_target,
                "matches_source": github_ref_points_to_sha(github_ref, source_sha),
            },
            "mirror_ready": mirror_ready,
            "release_count": len(releases),
            "latest_release_id": latest.get("id") if latest is not None else None,
            "conflicting_releases": conflicts,
            "mirror_state": "ready" if mirror_ready else "wait-for-mirror",
            "target_commitish": source_sha,
            "release_action": release_action,
            "asset_names_differing": differing_assets,
            "actual_assets": asset_summary(actual_assets),
            "expected_assets": asset_summary(expected),
            "asset_action": asset_action,
            "planned_after_mirror": {
                "release_actions": planned_release_actions,
                "target_commitish": source_sha,
                "draft": False,
                "prerelease": False,
                "asset_action": planned_asset_action,
            },
            "would_upload_assets": (
                asset_summary(expected) if planned_asset_action == "replace" else []
            ),
        },
    }


def publish(source_sha: str, expected: dict[str, bytes], forgejo_token: str, github_token: str) -> dict[str, Any]:
    # This first read is before any GitHub read, tag movement, mirror sync, or release write.
    require_forgejo_main_is_source(source_sha, forgejo_token, "publication")
    if not github_token:
        fail("GITHUB_TOKEN is required for GitHub release writes")

    # A conflicting release inventory blocks all writes, including the source-tag move.
    latest = require_single_latest_release(list_github_releases(github_token))
    no_op = exact_state_noop(source_sha, expected, forgejo_token, latest)
    if no_op is not None:
        return no_op
    forgejo_tag = ensure_forgejo_latest_tag(source_sha, forgejo_token)
    require_forgejo_main_is_source(source_sha, forgejo_token, "push_mirrors-sync")
    mirror_sync_http_status = sync_forgejo_push_mirrors(forgejo_token)
    wait_for_github_mirror(source_sha)

    latest = require_single_latest_release(list_github_releases(github_token))
    require_forgejo_main_is_source(source_sha, forgejo_token, "GitHub release write")
    if latest is None:
        latest = create_github_release(source_sha, github_token)
    latest = update_public_release(latest, source_sha, github_token)
    release_id = latest.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        fail("GitHub latest release omitted its numeric id")

    matches, _differences, _actual = github_assets_match(latest, expected)
    if not matches:
        delete_release_assets(release_id, latest, github_token)
        upload_assets(latest, expected, github_token)
    final_release, main_sha, mirror_ref, actual_assets = verify_github_release(
        source_sha, expected, github_token
    )
    return {
        "status": "published",
        "repo": OWNER_REPO,
        "source_sha": source_sha,
        "forgejo": {
            "tag": f"refs/tags/{LATEST_TAG}",
            **forgejo_tag,
            "push_mirrors_sync_http_status": mirror_sync_http_status,
        },
        "github": {
            "main_sha": main_sha,
            "mirror_tag": {
                "ref": f"refs/tags/{LATEST_TAG}",
                "object_sha": mirror_ref["object"]["sha"],
                "target_commit_sha": source_sha,
            },
            "release_id": final_release["id"],
            "assets": asset_summary(actual_assets),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", "--dry-run", action="store_true", help="perform GET-only reconciliation planning")
    args = parser.parse_args()
    source_sha = os.environ.get("CI_COMMIT_SHA", "")
    if not FULL_SHA.fullmatch(source_sha):
        print(json.dumps({"status": "error", "error": "CI_COMMIT_SHA must be exactly 40 lowercase hexadecimal characters"}, separators=(",", ":")))
        return 1
    forgejo_token = os.environ.get("FORGEJO_TOKEN", "").strip()
    github_token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not forgejo_token:
        print(json.dumps({"status": "error", "error": "FORGEJO_TOKEN is required"}, separators=(",", ":")))
        return 1
    try:
        if not args.plan:
            require_forgejo_main_is_source(source_sha, forgejo_token, "Forgejo release loading")
        release, payloads = load_forgejo_release(source_sha, forgejo_token)
        if args.plan:
            result = get_plan(source_sha, release, payloads, forgejo_token, github_token)
        elif release is None:
            result = {"status": "skipped", "reason": "Forgejo release is absent", "source_sha": source_sha}
        else:
            result = publish(source_sha, payloads, forgejo_token, github_token)
        print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
        return 0
    except SupersededError as exc:
        print(
            json.dumps(
                {
                    "status": "superseded",
                    "source_sha": source_sha,
                    "forgejo_main_sha": exc.main_sha,
                    "before": exc.boundary,
                },
                separators=(",", ":"),
            )
        )
        return 0
    except SyncError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, separators=(",", ":")))
        return 1
    except Exception as exc:
        # Keep unexpected errors useful without stringifying request objects.
        print(json.dumps({"status": "error", "error": f"unexpected {type(exc).__name__}"}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
