#!/usr/bin/env python3
"""Mint one bound agent enrollment token and store it without printing it."""

from __future__ import annotations

import argparse
import datetime as dt
import email.utils
import hashlib
import http.client
import json
import os
import re
import ssl
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
AWS_ERROR_CODE = re.compile(r"An error occurred \(([A-Za-z0-9][A-Za-z0-9._-]{0,127})\)")
AWS_LOCAL_ERROR_CLASSES = {
    "Unable to locate credentials": "MissingCredentials",
    "Could not connect to the endpoint URL": "EndpointConnection",
    "Failed to connect to proxy URL": "ProxyConnection",
    "SSL validation failed for": "TLSValidation",
    "usage: aws": "InvalidCLIArguments",
}
AWS_RETRYABLE_ERROR_CODES = {
    "InternalServerError",
    "RequestLimitExceeded",
    "ServiceUnavailable",
    "Throttling",
    "ThrottlingException",
    "TooManyUpdates",
}
AWS_UNKNOWN_OUTCOME_ERROR_CODES = {"InternalServerError", "ServiceUnavailable"}
AWS_REJECTED_ERROR_CODES = {
    "AccessDeniedException",
    "HierarchyLevelLimitExceededException",
    "HierarchyTypeMismatchException",
    "IncompatiblePolicyException",
    "InvalidAllowedPatternException",
    "InvalidKeyId",
    "InvalidPolicyAttributeException",
    "InvalidPolicyTypeException",
    "ParameterAlreadyExists",
    "ParameterLimitExceeded",
    "ParameterMaxVersionLimitExceeded",
    "PoliciesLimitExceededException",
    "UnsupportedOperationException",
    "ValidationException",
} | (AWS_RETRYABLE_ERROR_CODES - AWS_UNKNOWN_OUTCOME_ERROR_CODES)
MAX_RESPONSE_BYTES = 64 * 1024
API_TIMEOUT_SECONDS = 10
AWS_TIMEOUT_SECONDS = 30
SHARING_POLL_ATTEMPTS = 6
SHARING_POLL_SECONDS = 10
RETRY_SECONDS = 2
MAX_RETRY_AFTER_SECONDS = 30
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


class APIRequestRetryable(EnrollmentError):
    def __init__(
        self, message: str, *, retry_after_seconds: float | None = None
    ) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class APIRequestOutcomeUnknown(APIRequestRetryable):
    """The origin might have accepted a request whose result was not usable."""


class APIRequestRejectedRetryable(APIRequestRetryable):
    """The origin rejected a request that can be retried safely."""


class EnrollmentParameterOutcomeUnknown(EnrollmentError):
    """The SSM parameter update might have completed before the client timed out."""


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


def build_api_opener() -> urllib.request.OpenerDirector:
    # Use the interpreter's compiled trust paths, not SSL_CERT_FILE or
    # SSL_CERT_DIR from the runner environment. Do not send the bearer through
    # an ambient proxy.
    trust_paths = ssl.get_default_verify_paths()
    cafile = trust_paths.openssl_cafile
    capath = trust_paths.openssl_capath
    cafile = cafile if cafile and os.path.isfile(cafile) else None
    capath = capath if capath and os.path.isdir(capath) else None
    if cafile is None and capath is None:
        raise EnrollmentError("no compiled TLS trust store is available")
    try:
        tls_context = ssl.create_default_context(cafile=cafile, capath=capath)
    except (OSError, ssl.SSLError) as exc:
        raise EnrollmentError("could not load the compiled TLS trust store") from exc
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=tls_context),
        NoRedirectHandler,
    )


class LazyAPIOpener:
    """Delay trust-store loading until run() can sanitize any failure."""

    def __init__(self) -> None:
        self._opener: urllib.request.OpenerDirector | None = None

    def open(self, request: Any, *, timeout: float) -> Any:
        if self._opener is None:
            self._opener = build_api_opener()
        return self._opener.open(request, timeout=timeout)


NO_REDIRECT_OPENER = LazyAPIOpener()


def validate_api_endpoint(value: str, *, expected_sha256: str) -> str:
    if value != value.strip():
        raise EnrollmentError("sandbox API endpoint has leading or trailing whitespace")
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


def parse_retry_after(value: Any, *, now: dt.datetime | None = None) -> float | None:
    """Return a bounded Retry-After delay, or None for an invalid header."""
    if not isinstance(value, str):
        return None
    retry_after = value.strip()
    if retry_after.isascii() and retry_after.isdecimal():
        # Avoid converting an attacker-controlled integer with arbitrary size.
        significant = retry_after.lstrip("0") or "0"
        if len(significant) > 10:
            return float(MAX_RETRY_AFTER_SECONDS)
        return float(
            min(
                max(int(significant), RETRY_SECONDS),
                MAX_RETRY_AFTER_SECONDS,
            )
        )
    try:
        retry_at = email.utils.parsedate_to_datetime(retry_after)
    except (TypeError, ValueError, OverflowError):
        return None
    if retry_at.tzinfo is None:
        return None
    current = now or dt.datetime.now(dt.timezone.utc)
    seconds = (retry_at.astimezone(dt.timezone.utc) - current).total_seconds()
    return min(
        max(seconds, float(RETRY_SECONDS)),
        float(MAX_RETRY_AFTER_SECONDS),
    )


def api_request(
    api_endpoint: str,
    api_key: str,
    path: str,
    *,
    method: str = "GET",
    body: dict[str, Any] | None = None,
    idempotency_key: str = "",
    expected_status: int | tuple[int, ...] = 200,
    response_status: list[int] | None = None,
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
                # urllib raises HTTPError for non-2xx responses. Reaching this
                # branch means a success response had an unexpected contract,
                # so a mutation could have committed.
                raise APIRequestOutcomeUnknown(
                    f"qURL API returned HTTP {response.status} for the {method} request; expected one of {expected_statuses}"
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
        retry_after_seconds = parse_retry_after(
            exc.headers.get("Retry-After") if exc.headers is not None else None
        )
        try:
            exc.read(MAX_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException):
            pass
        finally:
            try:
                exc.close()
            except (OSError, http.client.HTTPException):
                pass
        message = f"qURL API rejected the {method} request with HTTP {exc.code}"
        if exc.code in {425, 429}:
            raise APIRequestRejectedRetryable(
                message,
                retry_after_seconds=retry_after_seconds,
            ) from exc
        if (
            exc.code == 408
            or 500 <= exc.code <= 599
            or (method in {"POST", "PUT"} and 300 <= exc.code <= 399)
        ):
            raise APIRequestOutcomeUnknown(
                message,
                retry_after_seconds=retry_after_seconds,
            ) from exc
        raise EnrollmentError(message) from exc
    except (OSError, http.client.HTTPException) as exc:
        raise APIRequestOutcomeUnknown(f"qURL API {method} request failed") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise APIRequestOutcomeUnknown("qURL API response exceeds 64 KiB")
    try:
        envelope = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise APIRequestOutcomeUnknown("qURL API returned invalid JSON") from exc
    if not isinstance(envelope, dict) or "data" not in envelope:
        raise APIRequestOutcomeUnknown("qURL API response has no data field")
    if response_status is not None:
        response_status[:] = [response.status]
    return envelope["data"]


def _put_parameter_command(region: str, parameter: str) -> list[str]:
    # KEY excludes non-ASCII and newlines, so text-mode paramfile expansion
    # preserves the validated token byte-for-byte. /dev/stdin requires the
    # POSIX environment pinned by the workflow's Ubuntu runner.
    # CI invokes the real AWS CLI against loopback and verifies the decoded
    # PutParameter payload, including Value, instead of checking argv alone.
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
    clean_env.pop("AWS_PROFILE", None)
    clean_env.pop("AWS_DEFAULT_PROFILE", None)
    clean_env.pop("AWS_DEFAULT_OUTPUT", None)
    clean_env.pop("AWS_ENDPOINT_URL", None)
    clean_env.pop("AWS_ENDPOINT_URL_SSM", None)
    clean_env.pop("AWS_ENDPOINT_URL_STS", None)
    clean_env.pop("AWS_CA_BUNDLE", None)
    clean_env.pop("AWS_DATA_PATH", None)
    for credential_variable in (
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_ROLE_ARN",
        "AWS_ROLE_SESSION_NAME",
        "BOTO_CONFIG",
    ):
        clean_env.pop(credential_variable, None)
    for proxy_variable in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "no_proxy",
        "all_proxy",
    ):
        clean_env.pop(proxy_variable, None)
    clean_env["AWS_CONFIG_FILE"] = os.devnull
    clean_env["AWS_SHARED_CREDENTIALS_FILE"] = os.devnull
    clean_env["AWS_CLI_FILE_ENCODING"] = "utf-8"
    # Make the single script-level retry below the complete retry budget.
    # Retrying the same SecureString value with --overwrite is idempotent.
    clean_env["AWS_RETRY_MODE"] = "standard"
    clean_env["AWS_MAX_ATTEMPTS"] = "1"
    clean_env["AWS_USE_FIPS_ENDPOINT"] = "false"
    clean_env["AWS_USE_DUALSTACK_ENDPOINT"] = "false"
    clean_env["AWS_EC2_METADATA_DISABLED"] = "true"
    clean_env["AWS_CLI_AUTO_PROMPT"] = "off"
    clean_env["AWS_PAGER"] = ""
    for attempt in range(2):
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
            # A timeout can happen after SSM commits. Do not issue a blind
            # retry when the first write outcome is unknown.
            raise EnrollmentParameterOutcomeUnknown(
                "AWS CLI timed out during the enrollment parameter update; the update may have completed"
            ) from exc
        except OSError as exc:
            raise EnrollmentError(
                "AWS CLI could not start for the enrollment parameter update"
            ) from exc
        if result.returncode == 0:
            return
        # AWS CLI stderr can contain credentials, profile names, and private
        # endpoints. Only emit a bounded service error code or reviewed class.
        match = AWS_ERROR_CODE.search(result.stderr or "")
        error_class = (
            match.group(1)
            if match
            else next(
                (
                    label
                    for signature, label in AWS_LOCAL_ERROR_CLASSES.items()
                    if signature in (result.stderr or "")
                ),
                "",
            )
        )
        if attempt == 0 and error_class in AWS_RETRYABLE_ERROR_CODES:
            time.sleep(RETRY_SECONDS)
            continue
        if error_class in AWS_UNKNOWN_OUTCOME_ERROR_CODES:
            raise EnrollmentParameterOutcomeUnknown(
                f"AWS returned {error_class} after the enrollment parameter update; the update may have completed"
            )
        if error_class in AWS_REJECTED_ERROR_CODES or error_class in set(
            AWS_LOCAL_ERROR_CLASSES.values()
        ):
            raise EnrollmentError(
                f"AWS rejected the enrollment parameter update with {error_class} (exit status {result.returncode})"
            )
        # An unclassified CLI failure can include a status-only service error,
        # a connection reset after SSM committed, or an unparseable response.
        # Do not expose stderr and do not tell the operator the write was rejected.
        raise EnrollmentParameterOutcomeUnknown(
            "AWS returned an unclassified failure after the enrollment parameter update; the update may have completed"
        )


def mint_and_install_enrollment(
    api_endpoint: str,
    api_key: str,
    target: str,
    generation: str,
    region: str,
    slug: str,
    parameter: str,
    *,
    now: dt.datetime | None = None,
) -> tuple[dt.datetime, str]:
    mint_path = "/v1/api-keys"
    mint_body = {
        "kind": "enrollment_token",
        "name": f"Sandbox {target} headless enrollment {generation}",
        "target": "agent",
        "claims": [{"type": "connector", "id": slug}],
        "expires_in": "1h",
    }
    # POST /v1/api-keys stores each idempotency response atomically with the key
    # for 24 hours. The selected target keeps every replica on a distinct
    # one-hour enrollment operation even when replicas share one route.
    mint_idempotency_key = f"headless-v2-{generation}-{target}"
    mint_failure: EnrollmentError | None = None
    mint_outcome_unknown = False
    mint_response_status: list[int] = []
    for attempt in range(2):
        try:
            mint_response_status.clear()
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
                response_status=mint_response_status,
            )
            break
        except APIRequestRetryable as exc:
            mint_failure = exc
            mint_outcome_unknown = mint_outcome_unknown or isinstance(
                exc, APIRequestOutcomeUnknown
            )
            if attempt == 0:
                retry_delay = (
                    exc.retry_after_seconds
                    if exc.retry_after_seconds is not None
                    else RETRY_SECONDS
                )
                time.sleep(min(max(retry_delay, 0.0), MAX_RETRY_AFTER_SECONDS))
        except EnrollmentError as exc:
            if mint_outcome_unknown:
                raise EnrollmentError(
                    "enrollment credential result is unknown; retry the same target and generation to recover the exact operation"
                ) from exc
            raise
    else:
        if not mint_outcome_unknown:
            raise EnrollmentError(
                "enrollment credential request was rejected after one bounded retry"
            ) from mint_failure
        raise EnrollmentError(
            "enrollment credential result is unknown; retry the same target and generation to recover the exact operation"
        ) from mint_failure
    credential_id = credential.get("key_id", "") if isinstance(credential, dict) else ""
    known_credential_id = bool(
        isinstance(credential_id, str)
        and re.fullmatch(r"key_[A-Za-z0-9]{8,64}", credential_id)
    )
    mint_warning = ""
    possible_extra_credential = mint_outcome_unknown and mint_response_status == [201]
    if possible_extra_credential:
        if known_credential_id:
            mint_warning = (
                f"installed credential {credential_id}, but the first mint outcome is "
                "unknown and another one-hour credential may remain live"
            )
        else:
            mint_warning = (
                "the first mint outcome is unknown and another one-hour credential may "
                "remain live; the installed credential ID is unavailable"
            )
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
        possible_extra_suffix = (
            "; the first mint outcome is also unknown and another one-hour credential may remain live"
            if possible_extra_credential
            else ""
        )
        if isinstance(exc, EnrollmentParameterOutcomeUnknown):
            if known_credential_id:
                raise EnrollmentError(
                    f"enrollment credential {credential_id} was minted, but its installation outcome is unknown; retry the same generation only while the recovered token has at least 45 minutes remaining to repeat the idempotent parameter write; do not revoke that non-secret credential ID unless the parameter is confirmed not to reference it{possible_extra_suffix}"
                ) from exc
            raise EnrollmentError(
                "an enrollment credential was minted, but its installation outcome is unknown and its credential ID is unavailable; retry the same generation only while the recovered token has at least 45 minutes remaining to repeat the idempotent parameter write, and do not assume the parameter is unchanged until the outcome is confirmed or the token expires within one hour"
                + possible_extra_suffix
            ) from exc
        if known_credential_id:
            raise EnrollmentError(
                f"enrollment credential {credential_id} was minted but not installed; retry the same generation only while the recovered token has at least 45 minutes remaining, otherwise use a new generation, or revoke that non-secret credential ID with JWT authority{possible_extra_suffix}"
            ) from exc
        raise EnrollmentError(
            "an enrollment credential was minted but not installed, and its credential ID is unavailable; retry the same target and generation to recover the exact operation, and wait up to one hour for expiry before using a new generation if the response remains invalid"
            + possible_extra_suffix
        ) from exc
    return expiry, mint_warning


def prepare_enrollment(
    api_endpoint: str,
    api_key: str,
    target: str,
    generation: str,
    region: str,
    *,
    now: dt.datetime | None = None,
) -> None:
    # The caller supplies one pre-provisioned qURL API key. Reuse it for the
    # complete bounded operation; this tool does not perform an OAuth or Auth0
    # client-credentials exchange per request or per resource.
    slug, parameter = TARGETS[target]
    # Pre-mint reads fail immediately; rerunning them cannot create state.
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
    sharing_idempotency_key = f"headless-sharing-v2-{generation}-{target}"
    sharing_transition_observed = False
    sharing_observed_on = False
    if desired_state == "off":
        # Recovery deliberately leaves the selected resource on. A fixed
        # replica can enroll only while sharing is on, and restoring off would
        # invalidate the enrollment that this operation prepares.
        put_failure: EnrollmentError | None = None
        last_put_rejection: EnrollmentError | None = None
        retry_put = False
        retry_delay: float | None = None
        for attempt in range(2):
            try:
                # The current qURL contract returns a 200 JSON envelope. A 204
                # is treated as unknown and reconciled by the GET poll because
                # it cannot confirm the exact state or serving epoch.
                api_request(
                    api_endpoint,
                    api_key,
                    resource_path + "/sharing",
                    method="PUT",
                    body={"desired_state": "on"},
                    idempotency_key=sharing_idempotency_key,
                )
                sharing_transition_observed = True
                break
            except APIRequestOutcomeUnknown as exc:
                # The server can apply the PUT before the response is lost. A
                # Retry-After response permits one bounded idempotent re-PUT;
                # the GET below resolves all other unknown outcomes.
                put_failure = exc
                retry_put = exc.retry_after_seconds is not None
                retry_delay = exc.retry_after_seconds
            except APIRequestRejectedRetryable as exc:
                last_put_rejection = exc
                retry_put = True
                retry_delay = exc.retry_after_seconds
            except EnrollmentError as exc:
                if put_failure is None:
                    raise
                last_put_rejection = exc
                break
            if attempt == 0 and retry_put:
                time.sleep(
                    min(
                        max(
                            retry_delay if retry_delay is not None else RETRY_SECONDS,
                            0.0,
                        ),
                        MAX_RETRY_AFTER_SECONDS,
                    )
                )
                continue
            break
        if not sharing_transition_observed and put_failure is None:
            raise EnrollmentError(
                "sharing update was rejected after one bounded retry"
            ) from last_put_rejection
        minimum_epoch = serving_epoch + 1
        last_poll_failure: EnrollmentError | None = None
        for attempt in range(SHARING_POLL_ATTEMPTS):
            poll_delay = float(SHARING_POLL_SECONDS)
            try:
                sharing = api_request(api_endpoint, api_key, resource_path + "/sharing")
                last_poll_failure = None
            except APIRequestRetryable as exc:
                sharing = None
                last_poll_failure = exc
                if exc.retry_after_seconds is not None:
                    poll_delay = min(
                        max(exc.retry_after_seconds, 0.0),
                        MAX_RETRY_AFTER_SECONDS,
                    )
            except EnrollmentError as exc:
                if sharing_transition_observed:
                    raise EnrollmentError(
                        "sharing status check was rejected after sharing changed from off to on during this run; sharing was left on"
                    ) from exc
                if sharing_observed_on:
                    raise EnrollmentError(
                        "sharing status check was rejected after sharing for this resource was observed on; sharing was left on"
                    ) from exc
                raise EnrollmentError(
                    "sharing status check was rejected after the sharing update outcome became unknown; sharing may have been applied before the response was lost and may have been left on"
                ) from exc
            observed_epoch = (
                sharing.get("serving_epoch") if isinstance(sharing, dict) else None
            )
            sharing_observed_on = sharing_observed_on or (
                isinstance(sharing, dict) and sharing.get("desired_state") == "on"
            )
            if (
                isinstance(observed_epoch, int)
                and not isinstance(observed_epoch, bool)
                and sharing.get("desired_state") == "on"
                and observed_epoch >= minimum_epoch
            ):
                sharing_transition_observed = True
                break
            if attempt + 1 < SHARING_POLL_ATTEMPTS:
                time.sleep(poll_delay)
        else:
            if last_poll_failure is not None:
                message = "sharing did not reach the required serving epoch because status checks failed"
                if sharing_transition_observed:
                    message += "; sharing changed from off to on during this run and was left on"
                elif sharing_observed_on:
                    message += (
                        "; sharing for this resource was observed on and was left on"
                    )
                elif put_failure is not None:
                    message += "; the sharing update outcome is unknown and sharing may have been applied before the response was lost and may have been left on"
                raise EnrollmentError(message) from last_poll_failure
            message = "sharing did not reach the required serving epoch"
            if sharing_transition_observed:
                message += (
                    "; sharing changed from off to on during this run and was left on"
                )
            elif sharing_observed_on:
                message += "; sharing for this resource was observed on and was left on"
            raise EnrollmentError(message)

    try:
        # Mint only after any required lifecycle transition is confirmed, so
        # failures before this point cannot leave a live credential behind.
        expiry, mint_warning = mint_and_install_enrollment(
            api_endpoint,
            api_key,
            target,
            generation,
            region,
            slug,
            parameter,
            now=now,
        )
    except EnrollmentError as exc:
        if sharing_transition_observed:
            raise EnrollmentError(
                "enrollment preparation failed after sharing changed from off to on during this run; sharing was left on"
            ) from exc
        raise
    if mint_warning:
        print(f"::warning::{mint_warning}", file=sys.stderr)
    if sharing_transition_observed:
        print(
            f"::notice::sharing for {target} changed from off to on during this run and was deliberately left on"
        )
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


def format_enrollment_error(exc: EnrollmentError) -> str:
    """Render only the reviewed EnrollmentError layers of a cause chain."""
    messages = [str(exc)]
    seen = {id(exc)}
    cause = exc.__cause__
    while isinstance(cause, EnrollmentError) and id(cause) not in seen:
        seen.add(id(cause))
        messages.append(str(cause))
        cause = cause.__cause__
    if len(messages) == 1:
        return messages[0]
    return f"{messages[0]} (caused by: {'; '.join(messages[1:])})"


def run() -> None:
    try:
        main()
    except EnrollmentError as exc:
        print(f"error: {format_enrollment_error(exc)}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print(
            f"error: unexpected internal failure ({type(exc).__name__})",
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    run()
