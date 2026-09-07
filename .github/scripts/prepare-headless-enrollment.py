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
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

KEY = re.compile(r"lv_live_[A-Za-z0-9_-]+\Z")
GENERATION = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
AWS_ERROR_CODE = re.compile(r"An error occurred \(([A-Za-z0-9][A-Za-z0-9._-]{0,127})\)")
AWS_LOCAL_ERROR_CLASSES = {
    "Unable to locate credentials": "MissingCredentials",
    "Could not connect to the endpoint URL": "EndpointConnection",
    # The AWS CLI emits this only when the endpoint handshake did not finish,
    # before it sends the PutParameter request. A read timeout is different:
    # it can happen after SSM commits and must remain an unknown outcome.
    "Connect timeout on endpoint URL": "EndpointConnectTimeout",
    "Failed to connect to proxy URL": "ProxyConnection",
    "SSL validation failed for": "TLSValidation",
    "usage: aws": "InvalidCLIArguments",
}
AWS_LOCAL_ERROR_LABELS = frozenset(AWS_LOCAL_ERROR_CLASSES.values())
AWS_RETRYABLE_ERROR_CODES = {
    "InternalServerError",
    "RequestLimitExceeded",
    "ServiceUnavailable",
    "Throttling",
    "ThrottlingException",
    "TooManyUpdates",
}
# These service errors can arrive after a write committed. Keep their result
# unknown unless reconciliation proves the stored value.
AWS_UNKNOWN_OUTCOME_ERROR_CODES = {
    "InternalServerError",
    "KMSInternalException",
    "ServiceUnavailable",
}
# These named failures prove that SSM rejected the PutParameter request before
# it committed. Keep unknown and future AWS error codes out of this allowlist.
AWS_REJECTED_ERROR_CODES = {
    "AccessDeniedException",
    "ExpiredToken",
    "ExpiredTokenException",
    "HierarchyLevelLimitExceededException",
    "HierarchyTypeMismatchException",
    "IncompleteSignature",
    "IncompleteSignatureException",
    "IncompatiblePolicyException",
    "InvalidAllowedPatternException",
    "InvalidClientTokenId",
    "InvalidKeyId",
    "InvalidPolicyAttributeException",
    "InvalidPolicyTypeException",
    "InvalidResourceId",
    "InvalidSignatureException",
    "KMSAccessDeniedException",
    "KMSInvalidStateException",
    "KMSKeyNotFound",
    # --overwrite makes this unexpected, but AWS documents it as a rejection;
    # classify it safely if a future CLI or service path returns it.
    "ParameterAlreadyExists",
    "ParameterLimitExceeded",
    "ParameterMaxVersionLimitExceeded",
    "ParameterNotFound",
    "ParameterPatternMismatchException",
    "PoliciesLimitExceededException",
    "RequestExpired",
    "SignatureDoesNotMatch",
    "UnrecognizedClientException",
    "UnsupportedOperationException",
    "UnsupportedParameterType",
    "ValidationException",
}
MAX_RESPONSE_BYTES = 64 * 1024
API_TIMEOUT_SECONDS = 10
AWS_CLI_CONNECT_TIMEOUT_SECONDS = 5
AWS_CLI_READ_TIMEOUT_SECONDS = 20
AWS_TIMEOUT_SECONDS = 35
# Allow up to two minutes of normal polling for an off-to-on serving epoch to
# propagate. The internal deadline below also bounds slow requests and
# Retry-After responses before the protected workflow's 12-minute hard cap.
SHARING_POLL_ATTEMPTS = 13
SHARING_POLL_SECONDS = 10
RETRY_SECONDS = 2
# Include process creation and interpreter overhead around the two wall-clock
# subprocess timeouts. The workflow step also keeps 60 seconds beyond the
# script's internal deadline for safe error reporting.
AWS_INSTALL_RESERVE_SECONDS = (2 * AWS_TIMEOUT_SECONDS) + RETRY_SECONDS + 5
# urllib applies API_TIMEOUT_SECONDS to each socket operation, not to the whole
# request. This reserve is a best-effort preflight. A slow mint can consume it,
# so the post-mint guard still reports the live credential without starting SSM.
ENROLLMENT_COMPLETION_RESERVE_SECONDS = (
    API_TIMEOUT_SECONDS + AWS_INSTALL_RESERVE_SECONDS
)
MAX_RETRY_AFTER_SECONDS = 30
SCRIPT_DEADLINE_SECONDS = 8 * 60
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
    """The request did not commit and can be retried safely."""


class EnrollmentParameterOutcomeUnknown(EnrollmentError):
    """The SSM parameter update might have completed before the client timed out."""


class EnrollmentDeadlineExceeded(EnrollmentError):
    """The script stopped before the workflow runner could kill it."""


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


def _operation_deadline(deadline: float | None) -> float:
    return time.monotonic() + SCRIPT_DEADLINE_SECONDS if deadline is None else deadline


def require_deadline_budget(deadline: float, reserve_seconds: float) -> None:
    if time.monotonic() + reserve_seconds >= deadline:
        raise EnrollmentDeadlineExceeded(
            "enrollment preparation reached its internal deadline"
        )


def sleep_before_deadline(
    delay_seconds: float, deadline: float, *, reserve_seconds: float
) -> None:
    require_deadline_budget(deadline, delay_seconds + reserve_seconds)
    time.sleep(delay_seconds)


def sharing_failure_message(
    message: str,
    *,
    sharing_transition_observed: bool,
    sharing_observed_on: bool,
    update_outcome_unknown: bool,
    final_poll_state_valid: bool,
) -> str:
    if sharing_transition_observed:
        return (
            message + "; sharing changed from off to on during this run and was left on"
        )
    if sharing_observed_on:
        return message + "; sharing for this resource was observed on and was left on"
    if update_outcome_unknown and not final_poll_state_valid:
        return (
            message
            + "; the sharing update outcome is unknown and sharing may have been applied before the response was lost and may have been left on"
        )
    return message


def _api_request(
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
            actual_status = response.status
            if actual_status not in expected_statuses:
                # urllib raises HTTPError for non-2xx responses. Reaching this
                # branch means a success response had an unexpected contract,
                # so a mutation could have committed.
                raise APIRequestOutcomeUnknown(
                    f"qURL API returned HTTP {actual_status} for the {method} request; expected one of {expected_statuses}"
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
    except urllib.error.URLError as exc:
        # DNS resolution, a refused TCP connection, and TLS certificate
        # verification all fail before urllib can send the HTTP request. Other
        # URL errors can happen after request bytes leave the runner, so their
        # outcomes remain unknown.
        if isinstance(
            exc.reason,
            (socket.gaierror, ConnectionRefusedError, ssl.SSLCertVerificationError),
        ):
            raise APIRequestRejectedRetryable(
                f"qURL API could not connect for the {method} request"
            ) from exc
        raise APIRequestOutcomeUnknown(f"qURL API {method} request failed") from exc
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
        response_status[:] = [actual_status]
    return envelope["data"]


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
    try:
        return _api_request(
            api_endpoint,
            api_key,
            path,
            method=method,
            body=body,
            idempotency_key=idempotency_key,
            expected_status=expected_status,
            response_status=response_status,
        )
    except EnrollmentDeadlineExceeded as exc:
        # A wall-clock alarm can interrupt any point in response processing.
        # Once a mutation starts, its outcome is unknown even if no complete
        # response reached the runner.
        if method in {"POST", "PUT"}:
            raise APIRequestOutcomeUnknown(
                f"qURL API {method} request reached the internal deadline"
            ) from exc
        raise


def api_request_before_deadline(
    deadline: float,
    api_endpoint: str,
    api_key: str,
    path: str,
    *,
    remaining_reserve_seconds: float = 0,
    **kwargs: Any,
) -> Any:
    require_deadline_budget(deadline, API_TIMEOUT_SECONDS + remaining_reserve_seconds)
    return api_request(api_endpoint, api_key, path, **kwargs)


def api_read_before_deadline(
    deadline: float, api_endpoint: str, api_key: str, path: str
) -> Any:
    """Perform one read with one bounded retry and no mutation ambiguity."""
    last_failure: APIRequestRetryable | None = None
    for attempt in range(2):
        try:
            return api_request_before_deadline(deadline, api_endpoint, api_key, path)
        except APIRequestRetryable as exc:
            last_failure = exc
            if attempt == 0:
                retry_delay = (
                    exc.retry_after_seconds
                    if exc.retry_after_seconds is not None
                    else RETRY_SECONDS
                )
                sleep_before_deadline(
                    min(max(retry_delay, 0.0), MAX_RETRY_AFTER_SECONDS),
                    deadline,
                    reserve_seconds=(
                        API_TIMEOUT_SECONDS + ENROLLMENT_COMPLETION_RESERVE_SECONDS
                    ),
                )
    raise EnrollmentError(
        "qURL API read failed after one bounded retry"
    ) from last_failure


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
        "--cli-connect-timeout",
        str(AWS_CLI_CONNECT_TIMEOUT_SECONDS),
        "--cli-read-timeout",
        str(AWS_CLI_READ_TIMEOUT_SECONDS),
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


def _put_parameter(region: str, parameter: str, token: str) -> None:
    clean_env = os.environ.copy()
    # main() already removes these values. Remove them again here so direct
    # library-style calls cannot pass qURL bearer material to the AWS process.
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
    clean_env.pop("SSL_CERT_FILE", None)
    clean_env.pop("SSL_CERT_DIR", None)
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
        # A returned service error means the request finished, so repeating the
        # same value with --overwrite is idempotent. A subprocess timeout can
        # leave the original request in flight and is never retried blindly.
        # Codes in both sets retry once because the value is byte-identical;
        # only a second failure is reported as outcome unknown.
        if attempt == 0 and error_class in AWS_RETRYABLE_ERROR_CODES:
            time.sleep(RETRY_SECONDS)
            continue
        if error_class in AWS_UNKNOWN_OUTCOME_ERROR_CODES:
            raise EnrollmentParameterOutcomeUnknown(
                f"AWS returned {error_class} after the enrollment parameter update; the update may have completed"
            )
        if error_class in AWS_RETRYABLE_ERROR_CODES:
            raise EnrollmentError(
                f"AWS temporarily rejected the enrollment parameter update with {error_class} after one bounded retry; retrying the same generation is safe"
            )
        if (
            error_class in AWS_REJECTED_ERROR_CODES
            or error_class in AWS_LOCAL_ERROR_LABELS
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


def put_parameter(
    region: str,
    parameter: str,
    token: str,
    *,
    on_success: Callable[[], None] | None = None,
) -> None:
    try:
        _put_parameter(region, parameter, token)
        # The successful SSM response is the final outcome-changing event.
        # Disarm the process deadline before this function returns so later
        # notices cannot turn a completed installation into a false failure.
        if on_success is not None:
            on_success()
    except EnrollmentDeadlineExceeded as exc:
        # The POSIX alarm can interrupt the AWS child, response processing, or
        # retry delay after PutParameter starts. Keep every such outcome
        # unknown, even when subprocess.run kills the local child.
        raise EnrollmentParameterOutcomeUnknown(
            "the internal deadline was reached during the enrollment parameter update; the update may have completed"
        ) from exc


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
    deadline: float | None = None,
    on_install_complete: Callable[[], None] | None = None,
) -> tuple[dt.datetime, str]:
    operation_deadline = _operation_deadline(deadline)
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
    # Reserve the full write path before any POST can create a live credential.
    # Repeat this reservation before a retry so its sleep and request cannot
    # consume the SSM installation budget.
    require_deadline_budget(
        operation_deadline,
        ENROLLMENT_COMPLETION_RESERVE_SECONDS,
    )
    for attempt in range(2):
        try:
            mint_response_status.clear()
            credential = api_request_before_deadline(
                operation_deadline,
                api_endpoint,
                api_key,
                mint_path,
                method="POST",
                body=mint_body,
                idempotency_key=mint_idempotency_key,
                # The outer preflight reserves the complete mint-and-install
                # path. This request reserves its socket window; the post-mint
                # guard decides whether SSM can still start safely.
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
                bounded_retry_delay = min(
                    max(retry_delay, 0.0), MAX_RETRY_AFTER_SECONDS
                )
                try:
                    sleep_before_deadline(
                        bounded_retry_delay,
                        operation_deadline,
                        reserve_seconds=ENROLLMENT_COMPLETION_RESERVE_SECONDS,
                    )
                except EnrollmentDeadlineExceeded as deadline_exc:
                    if mint_outcome_unknown:
                        raise EnrollmentError(
                            "enrollment credential result is unknown; retry the same target and generation to recover the exact operation"
                        ) from deadline_exc
                    raise
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
        # Claims are the credential authority boundary. Reject extra claims and
        # additive claim fields until this recovery contract is reviewed again.
        # The wrapper below reports the live key ID and revocation guidance.
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
        require_deadline_budget(operation_deadline, AWS_INSTALL_RESERVE_SECONDS)
        put_parameter(
            region,
            parameter,
            token,
            on_success=on_install_complete,
        )
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
    deadline: float | None = None,
    on_install_complete: Callable[[], None] | None = None,
) -> None:
    # The caller supplies one pre-provisioned qURL API key. Reuse it for the
    # complete bounded operation; this tool does not perform an OAuth or Auth0
    # client-credentials exchange per request or per resource.
    operation_deadline = _operation_deadline(deadline)
    slug, parameter = TARGETS[target]
    # These pre-mint reads can retry once because they cannot create state.
    resources = api_read_before_deadline(
        operation_deadline,
        api_endpoint,
        api_key,
        "/v1/resources?" + urllib.parse.urlencode({"slug": slug}),
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

    sharing = api_read_before_deadline(
        operation_deadline, api_endpoint, api_key, resource_path + "/sharing"
    )
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
    # Include the observed epoch so an off -> on recovery after a later off
    # transition cannot replay the response from an older sharing lifecycle.
    # Immediate retries still reuse the same key and start state.
    sharing_idempotency_key = (
        f"headless-sharing-v2-{generation}-{target}-{serving_epoch}"
    )
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
                api_request_before_deadline(
                    operation_deadline,
                    api_endpoint,
                    api_key,
                    resource_path + "/sharing",
                    remaining_reserve_seconds=ENROLLMENT_COMPLETION_RESERVE_SECONDS,
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
                bounded_retry_delay = min(
                    max(
                        retry_delay if retry_delay is not None else RETRY_SECONDS,
                        0.0,
                    ),
                    MAX_RETRY_AFTER_SECONDS,
                )
                try:
                    sleep_before_deadline(
                        bounded_retry_delay,
                        operation_deadline,
                        reserve_seconds=(
                            API_TIMEOUT_SECONDS + ENROLLMENT_COMPLETION_RESERVE_SECONDS
                        ),
                    )
                except EnrollmentDeadlineExceeded as deadline_exc:
                    raise EnrollmentError(
                        sharing_failure_message(
                            "enrollment preparation reached its internal deadline",
                            sharing_transition_observed=sharing_transition_observed,
                            sharing_observed_on=sharing_observed_on,
                            update_outcome_unknown=put_failure is not None,
                            final_poll_state_valid=False,
                        )
                    ) from deadline_exc
                continue
            break
        if not sharing_transition_observed and put_failure is None:
            raise EnrollmentError(
                "sharing update was rejected after one bounded retry"
            ) from last_put_rejection
        minimum_epoch = serving_epoch + 1
        last_poll_failure: EnrollmentError | None = None
        final_poll_state_valid = False
        for attempt in range(SHARING_POLL_ATTEMPTS):
            poll_delay = float(SHARING_POLL_SECONDS)
            try:
                sharing = api_request_before_deadline(
                    operation_deadline,
                    api_endpoint,
                    api_key,
                    resource_path + "/sharing",
                    # Keep the complete mint request and SSM installation
                    # budget available after this status request finishes.
                    remaining_reserve_seconds=ENROLLMENT_COMPLETION_RESERVE_SECONDS,
                )
                last_poll_failure = None
            except APIRequestRetryable as exc:
                sharing = None
                last_poll_failure = exc
                if exc.retry_after_seconds is not None:
                    poll_delay = min(
                        max(exc.retry_after_seconds, 0.0),
                        MAX_RETRY_AFTER_SECONDS,
                    )
            except EnrollmentDeadlineExceeded as exc:
                raise EnrollmentError(
                    sharing_failure_message(
                        "enrollment preparation reached its internal deadline",
                        sharing_transition_observed=sharing_transition_observed,
                        sharing_observed_on=sharing_observed_on,
                        update_outcome_unknown=put_failure is not None,
                        # This status request did not return a final state.
                        final_poll_state_valid=False,
                    )
                ) from exc
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
            observed_desired_state = (
                sharing.get("desired_state") if isinstance(sharing, dict) else None
            )
            final_poll_state_valid = (
                observed_desired_state in {"off", "on"}
                and isinstance(observed_epoch, int)
                and not isinstance(observed_epoch, bool)
                and observed_epoch >= 0
            )
            sharing_observed_on = sharing_observed_on or (
                observed_desired_state == "on"
            )
            if (
                isinstance(observed_epoch, int)
                and not isinstance(observed_epoch, bool)
                and observed_desired_state == "on"
                and observed_epoch >= minimum_epoch
            ):
                sharing_transition_observed = True
                break
            if attempt + 1 < SHARING_POLL_ATTEMPTS:
                try:
                    sleep_before_deadline(
                        poll_delay,
                        operation_deadline,
                        reserve_seconds=(
                            API_TIMEOUT_SECONDS + ENROLLMENT_COMPLETION_RESERVE_SECONDS
                        ),
                    )
                except EnrollmentDeadlineExceeded as exc:
                    raise EnrollmentError(
                        sharing_failure_message(
                            "enrollment preparation reached its internal deadline",
                            sharing_transition_observed=sharing_transition_observed,
                            sharing_observed_on=sharing_observed_on,
                            update_outcome_unknown=put_failure is not None,
                            final_poll_state_valid=final_poll_state_valid,
                        )
                    ) from exc
        else:
            if last_poll_failure is not None:
                message = sharing_failure_message(
                    "sharing did not reach the required serving epoch because status checks failed",
                    sharing_transition_observed=sharing_transition_observed,
                    sharing_observed_on=sharing_observed_on,
                    update_outcome_unknown=put_failure is not None,
                    # The last status request failed, so an earlier valid off
                    # observation is not a final reconciliation result.
                    final_poll_state_valid=False,
                )
                raise EnrollmentError(message) from last_poll_failure
            raise EnrollmentError(
                sharing_failure_message(
                    "sharing did not reach the required serving epoch",
                    sharing_transition_observed=sharing_transition_observed,
                    sharing_observed_on=sharing_observed_on,
                    update_outcome_unknown=put_failure is not None,
                    final_poll_state_valid=final_poll_state_valid,
                )
            ) from last_put_rejection

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
            deadline=operation_deadline,
            on_install_complete=on_install_complete,
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
            f"::notice::sharing for {target} changed from off to on during this run and was deliberately left on",
            file=sys.stderr,
        )
    print(
        f"prepared one-hour enrollment for {target} at serving epoch {observed_epoch}; "
        f"expires {expiry.isoformat()}"
    )


def main(
    *,
    deadline: float | None = None,
    on_install_complete: Callable[[], None] | None = None,
) -> None:
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
    prepare_enrollment(
        api_endpoint,
        api_key,
        args.target,
        args.generation,
        args.region,
        deadline=deadline,
        on_install_complete=on_install_complete,
    )


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


def _raise_script_deadline(_signum: int, _frame: Any) -> None:
    raise EnrollmentDeadlineExceeded(
        "enrollment preparation reached its internal deadline"
    )


def run() -> None:
    # Compute the checkpoint deadline before arming the timer. It can be
    # slightly earlier than the alarm, but never optimistically later.
    script_deadline = time.monotonic() + SCRIPT_DEADLINE_SECONDS
    installation_complete = False

    def deadline_handler(signum: int, frame: Any) -> None:
        # The completion flag is set as part of the successful PutParameter
        # path. It also makes a pending alarm harmless before setitimer(0)
        # removes any future alarm.
        if installation_complete:
            return
        _raise_script_deadline(signum, frame)

    def complete_installation() -> None:
        nonlocal installation_complete
        installation_complete = True
        signal.setitimer(signal.ITIMER_REAL, 0)

    previous_alarm_handler = signal.signal(signal.SIGALRM, deadline_handler)
    signal.setitimer(signal.ITIMER_REAL, SCRIPT_DEADLINE_SECONDS)
    try:
        main(
            deadline=script_deadline,
            on_install_complete=complete_installation,
        )
    except EnrollmentError as exc:
        print(f"error: {format_enrollment_error(exc)}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print(
            f"error: unexpected internal failure ({type(exc).__name__})",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_alarm_handler)


if __name__ == "__main__":
    run()
