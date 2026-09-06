#!/usr/bin/env python3
"""Mint one bound agent enrollment token and store it without printing it."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

KEY = re.compile(r"lv_live_[A-Za-z0-9_-]+\Z")
GENERATION = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
AWS_ERROR_CODE = re.compile(r"An error occurred \(([A-Za-z][A-Za-z0-9._-]{0,127})\)")
MAX_RESPONSE_BYTES = 64 * 1024
API_TIMEOUT_SECONDS = 10
AWS_TIMEOUT_SECONDS = 30
SHARING_POLL_ATTEMPTS = 6
SHARING_POLL_SECONDS = 2
MINT_RETRY_SECONDS = 2
TARGETS = {
    "fileviewer-nhp-replica-a": (
        "fileviewer-sandbox",
        "/qurl-s3-connector/fileviewer-nhp/replica-a/bootstrap",
    ),
    "fileviewer-nhp-replica-b": (
        "fileviewer-sandbox",
        "/qurl-s3-connector/fileviewer-nhp/replica-b/bootstrap",
    ),
    "fileviewer-nhp-replica-c": (
        "fileviewer-sandbox",
        "/qurl-s3-connector/fileviewer-nhp/replica-c/bootstrap",
    ),
    "uploader-nhp-replica-a": (
        "uploader-sandbox",
        "/qurl-s3-connector/uploader-nhp/replica-a/bootstrap",
    ),
    "uploader-nhp-replica-b": (
        "uploader-sandbox",
        "/qurl-s3-connector/uploader-nhp/replica-b/bootstrap",
    ),
    "uploader-nhp-replica-c": (
        "uploader-sandbox",
        "/qurl-s3-connector/uploader-nhp/replica-c/bootstrap",
    ),
    "detect-nhp-replica-a": (
        "detect-sandbox",
        "/qurl-s3-connector/detect-nhp/replica-a/bootstrap",
    ),
    "detect-nhp-replica-b": (
        "detect-sandbox",
        "/qurl-s3-connector/detect-nhp/replica-b/bootstrap",
    ),
    "detect-nhp-replica-c": (
        "detect-sandbox",
        "/qurl-s3-connector/detect-nhp/replica-c/bootstrap",
    ),
    "watermark-nhp-replica-a": (
        "watermark-sandbox",
        "/qurl-watermark-service/nhp/replica-a/bootstrap",
    ),
    "watermark-nhp-replica-b": (
        "watermark-sandbox",
        "/qurl-watermark-service/nhp/replica-b/bootstrap",
    ),
    "watermark-nhp-replica-c": (
        "watermark-sandbox",
        "/qurl-watermark-service/nhp/replica-c/bootstrap",
    ),
}


class EnrollmentError(RuntimeError):
    pass


class APIRequestOutcomeUnknown(EnrollmentError):
    """The origin might have accepted a request whose result was not usable."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


NO_REDIRECT_OPENER = urllib.request.build_opener(NoRedirectHandler)


def validate_api_endpoint(value: str, *, expected_sha256: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise EnrollmentError("sandbox API endpoint is invalid") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise EnrollmentError("sandbox API endpoint must be one HTTPS origin")
    origin = value.rstrip("/")
    if hashlib.sha256(origin.encode()).hexdigest() != expected_sha256:
        raise EnrollmentError("sandbox API endpoint does not match the reviewed origin")
    return origin


def validate_inputs(target: str, generation: str, region: str) -> None:
    if target not in TARGETS:
        raise EnrollmentError("enrollment target is invalid")
    if not GENERATION.fullmatch(generation):
        raise EnrollmentError("enrollment generation is invalid")
    if region != "us-east-2":
        raise EnrollmentError("enrollment recovery is limited to us-east-2")


def parse_expiry(value: Any, *, now: dt.datetime | None = None) -> dt.datetime:
    try:
        expiry = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        offset = expiry.utcoffset()
    except (AttributeError, TypeError, ValueError) as exc:
        raise EnrollmentError("enrollment token expiry is invalid") from exc
    if offset is None:
        raise EnrollmentError("enrollment token expiry must include a timezone")
    current = now or dt.datetime.now(dt.timezone.utc)
    if expiry - current < dt.timedelta(minutes=45):
        raise EnrollmentError(
            "enrollment token has less than 45 minutes remaining; use a new generation"
        )
    if expiry - current > dt.timedelta(hours=1, minutes=5):
        raise EnrollmentError(
            "enrollment token lifetime exceeds one hour plus clock-skew tolerance"
        )
    return expiry


def api_request(
    api_endpoint: str,
    api_key: str,
    path: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    idempotency_key: str = "",
    expected_status: int | tuple[int, ...] = 200,
) -> Any:
    headers = {"Authorization": f"Bearer {api_key}", "Accept": "application/json"}
    raw_body = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        raw_body = json.dumps(body, separators=(",", ":")).encode()
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(
        api_endpoint + path, data=raw_body, headers=headers, method=method
    )
    expected_statuses = (
        (expected_status,) if isinstance(expected_status, int) else expected_status
    )
    try:
        with NO_REDIRECT_OPENER.open(request, timeout=API_TIMEOUT_SECONDS) as response:
            if response.status not in expected_statuses:
                error_class = (
                    APIRequestOutcomeUnknown
                    if 200 <= response.status < 300
                    else EnrollmentError
                )
                raise error_class(
                    f"qURL API returned HTTP {response.status} for {method} {path}; expected one of {expected_statuses}"
                )
            content_types = response.headers.get_all("Content-Type", [])
            if (
                len(content_types) != 1
                or content_types[0].split(";", 1)[0].strip().lower()
                != "application/json"
            ):
                raise APIRequestOutcomeUnknown(
                    "qURL API response Content-Type is not one application/json media type"
                )
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        try:
            exc.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException):
            pass
        finally:
            try:
                exc.close()
            except (OSError, http.client.HTTPException):
                pass
        error_class = (
            APIRequestOutcomeUnknown
            if exc.code == 408 or exc.code >= 500
            else EnrollmentError
        )
        raise error_class(
            f"qURL API rejected {method} {path} with HTTP {exc.code}"
        ) from exc
    except (OSError, http.client.HTTPException) as exc:
        raise APIRequestOutcomeUnknown(
            f"qURL API request failed for {method} {path}"
        ) from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise APIRequestOutcomeUnknown("qURL API response exceeds 64 KiB")
    try:
        envelope = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise APIRequestOutcomeUnknown("qURL API returned invalid JSON") from exc
    if not isinstance(envelope, dict) or "data" not in envelope:
        raise APIRequestOutcomeUnknown("qURL API response has no data field")
    return envelope["data"]


def _put_parameter_command(region: str, parameter: str) -> list[str]:
    # KEY excludes non-ASCII and newlines, so text-mode paramfile expansion
    # preserves the validated token byte-for-byte.
    # The paired Terraform foundation creates every reviewed parameter under
    # the AWS-managed alias/aws/ssm key. The recovery role therefore needs no
    # customer-managed KMS authority and cannot silently select another key.
    return [
        "aws",
        "ssm",
        "put-parameter",
        "--region",
        region,
        "--name",
        parameter,
        "--type",
        "SecureString",
        "--overwrite",
        "--value",
        "file:///dev/stdin",
    ]


def put_parameter(region: str, parameter: str, token: str) -> None:
    clean_env = os.environ.copy()
    clean_env.pop("QURL_SANDBOX_API_KEY", None)
    clean_env.pop("QURL_SANDBOX_API_ENDPOINT", None)
    clean_env.pop("QURL_SANDBOX_API_ENDPOINT_SHA256", None)
    try:
        result = subprocess.run(
            _put_parameter_command(region, parameter),
            input=token,
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=clean_env,
            check=False,
            timeout=AWS_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        raise EnrollmentError(
            "AWS CLI timed out during the enrollment parameter update"
        ) from exc
    except OSError as exc:
        raise EnrollmentError(
            "AWS CLI could not start for the enrollment parameter update"
        ) from exc
    if result.returncode != 0:
        match = AWS_ERROR_CODE.search(result.stderr or "")
        error_code = f" with {match.group(1)}" if match else ""
        raise EnrollmentError(
            f"AWS rejected the enrollment parameter update{error_code} (exit status {result.returncode})"
        )


def prepare_enrollment(
    api_endpoint: str,
    api_key: str,
    target: str,
    generation: str,
    region: str,
    *,
    now: dt.datetime | None = None,
) -> None:
    slug, parameter = TARGETS[target]
    resources = api_request(
        api_endpoint, api_key, "/v1/resources?" + urllib.parse.urlencode({"slug": slug})
    )
    if (
        not isinstance(resources, list)
        or len(resources) != 1
        or not isinstance(resources[0], dict)
    ):
        raise EnrollmentError("connector slug did not resolve to exactly one resource")
    resource = resources[0]
    if (
        resource.get("slug") != slug
        or resource.get("type") != "tunnel"
        or resource.get("status") != "active"
    ):
        raise EnrollmentError("connector resource is not one active tunnel")
    resource_id = resource.get("resource_id", "")
    if not isinstance(resource_id, str) or not resource_id:
        raise EnrollmentError("connector resource has no resource ID")
    resource_path = "/v1/resources/" + urllib.parse.quote(resource_id, safe="")

    sharing = api_request(api_endpoint, api_key, resource_path + "/sharing")
    desired_state = sharing.get("desired_state") if isinstance(sharing, dict) else None
    serving_epoch = sharing.get("serving_epoch") if isinstance(sharing, dict) else None
    if (
        desired_state not in {"off", "on"}
        or not isinstance(serving_epoch, int)
        or isinstance(serving_epoch, bool)
        or serving_epoch < 0
    ):
        raise EnrollmentError("sharing state is invalid")
    # Verified against the current control-plane SetSharingDesiredState contract:
    # desired state and serving epoch are written in one atomic update. An on/0
    # image cannot come from a valid start transition.
    if desired_state == "on" and serving_epoch == 0:
        raise EnrollmentError(
            "sharing state is invalid: desired on requires a positive serving epoch"
        )

    observed_epoch = serving_epoch
    if desired_state == "off":
        put_failure: EnrollmentError | None = None
        try:
            api_request(
                api_endpoint,
                api_key,
                resource_path + "/sharing",
                method="PUT",
                body={"desired_state": "on"},
            )
        except EnrollmentError as exc:
            # The server can apply the PUT before the response is lost. The GET
            # below decides whether it is safe to continue and keeps retries
            # possible when the mutation did not land.
            put_failure = exc
        minimum_epoch = serving_epoch + 1
        last_poll_failure: EnrollmentError | None = None
        for attempt in range(SHARING_POLL_ATTEMPTS):
            try:
                sharing = api_request(api_endpoint, api_key, resource_path + "/sharing")
                last_poll_failure = None
            except EnrollmentError as exc:
                sharing = None
                last_poll_failure = exc
            observed_epoch = (
                sharing.get("serving_epoch") if isinstance(sharing, dict) else None
            )
            if (
                isinstance(observed_epoch, int)
                and not isinstance(observed_epoch, bool)
                and sharing.get("desired_state") == "on"
                and observed_epoch >= minimum_epoch
            ):
                break
            if attempt + 1 < SHARING_POLL_ATTEMPTS:
                time.sleep(SHARING_POLL_SECONDS)
        else:
            if put_failure is not None:
                raise EnrollmentError(
                    "sharing did not reach the required serving epoch after its update failed"
                ) from put_failure
            if last_poll_failure is not None:
                raise EnrollmentError(
                    "sharing did not reach the required serving epoch because status checks failed"
                ) from last_poll_failure
            raise EnrollmentError("sharing did not reach the required serving epoch")

    # Mint only after any required lifecycle transition is confirmed, so failures
    # before this point cannot leave a live enrollment credential behind.
    mint_path = "/v1/api-keys"
    mint_body = {
        "kind": "enrollment_token",
        "name": f"Sandbox {target} headless enrollment {generation}",
        "target": "agent",
        "claims": [{"type": "connector", "id": slug}],
        "expires_in": "1h",
    }
    # The selected target, not only the shared Connector slug, is part of the
    # idempotency key. Each fixed replica gets a distinct one-hour enrollment
    # token even when all replicas share one route identity.
    mint_idempotency_key = f"headless-v2-{generation}-{target}"
    mint_failure: EnrollmentError | None = None
    for attempt in range(2):
        try:
            credential = api_request(
                api_endpoint,
                api_key,
                mint_path,
                method="POST",
                body=mint_body,
                idempotency_key=mint_idempotency_key,
                # 201 is a new operation. 200 is the byte-exact result from an
                # idempotent retry after the first response was lost.
                expected_status=(200, 201),
            )
            break
        except APIRequestOutcomeUnknown as exc:
            mint_failure = exc
            if attempt == 0:
                time.sleep(MINT_RETRY_SECONDS)
    else:
        raise EnrollmentError(
            "enrollment credential result is unknown; retry the same target and generation to recover the exact operation"
        ) from mint_failure
    credential_id = credential.get("key_id", "") if isinstance(credential, dict) else ""
    try:
        expected_claims = [{"type": "connector", "id": slug}]
        if (
            not isinstance(credential, dict)
            or credential.get("kind") != "enrollment_token"
            or credential.get("target") != "agent"
            or credential.get("claims") != expected_claims
        ):
            raise EnrollmentError(
                "qURL API did not confirm the exact enrollment authority"
            )
        token = credential.get("api_key", "")
        if not isinstance(token, str) or not KEY.fullmatch(token):
            raise EnrollmentError("enrollment token is missing or malformed")
        expiry = parse_expiry(credential.get("expires_at", ""), now=now)
        # The recovery role intentionally has write-only SSM access, so it
        # cannot preflight this write. The API retains the idempotency
        # operation for 24 hours, while the deployment preflight accepts a
        # parameter write for only 15 minutes. A new generation creates a new
        # operation after that deployment window; every minted token expires
        # within one hour.
        put_parameter(region, parameter, token)
    except EnrollmentError as exc:
        if isinstance(credential_id, str) and re.fullmatch(
            r"key_[A-Za-z0-9]{8,64}", credential_id
        ):
            raise EnrollmentError(
                f"enrollment credential {credential_id} was minted but not installed: {exc}; retry the same generation only while the recovered token has at least 45 minutes remaining, otherwise use a new generation, or revoke that non-secret credential ID with JWT authority"
            ) from exc
        raise
    print(
        f"prepared one-hour enrollment for {target} at serving epoch {observed_epoch}; "
        f"expires {expiry.isoformat()}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--generation", required=True)
    parser.add_argument("--region", required=True)
    args = parser.parse_args()
    api_key = os.environ.pop("QURL_SANDBOX_API_KEY", "")
    api_endpoint_value = os.environ.pop("QURL_SANDBOX_API_ENDPOINT", "")
    expected_endpoint_sha256 = os.environ.pop("QURL_SANDBOX_API_ENDPOINT_SHA256", "")
    if not KEY.fullmatch(api_key):
        raise EnrollmentError("QURL_SANDBOX_API_KEY is missing or malformed")
    if not SHA256_HEX.fullmatch(expected_endpoint_sha256):
        raise EnrollmentError(
            "QURL_SANDBOX_API_ENDPOINT_SHA256 is missing or malformed"
        )
    api_endpoint = validate_api_endpoint(
        api_endpoint_value, expected_sha256=expected_endpoint_sha256
    )
    validate_inputs(args.target, args.generation, args.region)
    prepare_enrollment(api_endpoint, api_key, args.target, args.generation, args.region)


if __name__ == "__main__":
    try:
        main()
    except EnrollmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
