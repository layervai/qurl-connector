from __future__ import annotations

import datetime as dt
import http.server
import importlib.util
import pathlib
import re
import shutil
import sys
import threading
import unittest
from unittest import mock


SCRIPT = pathlib.Path(__file__).with_name("prepare-headless-enrollment.py")
WORKFLOW = SCRIPT.parent.parent / "workflows" / "rotate-tunnel-enrollment.yml"
VALIDATE_WORKFLOW = SCRIPT.parent.parent / "workflows" / "validate-workflows.yml"
SANITIZER = SCRIPT.with_name("public_source_sanitization_test.go")
GITIGNORE = SCRIPT.parent.parent.parent / ".gitignore"
MAKEFILE = SCRIPT.parent.parent.parent / "Makefile"
SPEC = importlib.util.spec_from_file_location("prepare_headless_enrollment", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
FIXED_NOW = dt.datetime(2026, 9, 4, 18, 0, tzinfo=dt.timezone.utc)
VALID_EXPIRY = "2026-09-04T19:00:00Z"


class FakeResponse:
    def __init__(
        self, body: bytes, *, status: int = 200, content_types: list[str] | None = None
    ) -> None:
        self.body = body
        self.status = status
        self.headers = mock.Mock()
        self.headers.get_all.return_value = (
            ["application/json"] if content_types is None else content_types
        )

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _limit: int) -> bytes:
        return self.body


class PrepareHeadlessEnrollmentTest(unittest.TestCase):
    def test_generated_python_tool_directories_are_ignored(self) -> None:
        entries = set(GITIGNORE.read_text().splitlines())
        self.assertTrue({".ruff_cache/", ".venv/", "/venv/"} <= entries)

    def test_workflow_exposes_every_reviewed_target_and_uses_target_selector(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text()
        options_match = re.search(
            r"(?ms)^      target:\n.*?^        options:\n((?:          - [a-z0-9-]+\n)+)",
            workflow,
        )
        self.assertIsNotNone(options_match)
        options = {
            line.removeprefix("          - ")
            for line in options_match.group(1).splitlines()
        }
        self.assertEqual(options, set(MODULE.TARGETS))
        self.assertIn('--target "$RECOVERY_TARGET"', workflow)
        self.assertNotIn("--api-endpoint", workflow)
        self.assertIn("RECOVERY_TARGET: ${{ inputs.target }}", workflow)
        self.assertIn("name: Rotate ${{ inputs.target }}", workflow)
        self.assertIn(
            "group: rotate-sandbox-tunnel-enrollment-${{ inputs.target }}", workflow
        )
        self.assertIn("reuse for immediate retries", workflow)
        self.assertIn("less than 45 minutes left", workflow)
        self.assertNotIn("matrix:", workflow)
        self.assertNotIn('--slug "$RECOVERY_SLUG"', workflow)
        self.assertNotIn("both", options)
        for target in options:
            for other in options - {target}:
                self.assertFalse(
                    target.endswith("-" + other),
                    f"target suffixes can collide in an idempotency key: {target}, {other}",
                )

    def test_workflow_fails_before_aws_when_protected_environment_is_missing(
        self,
    ) -> None:
        workflow = WORKFLOW.read_text()
        verify_job = workflow.index("  verify-environment:")
        rotate_job = workflow.index("  rotate:")
        preflight = workflow.index("- name: Validate protected sandbox environment")
        aws = workflow.index("- name: Configure narrow AWS credentials")
        aws_cli = workflow.index("- name: Require tested AWS CLI major")
        prepare = workflow.index("- name: Prepare reviewed enrollment tokens")
        self.assertLess(verify_job, rotate_job)
        self.assertLess(preflight, aws_cli)
        self.assertLess(aws_cli, aws)
        self.assertLess(aws, prepare)
        self.assertIn("if ! aws_version=$(aws --version 2>&1); then", workflow)
        self.assertIn("AWS CLI v2, but aws is unavailable", workflow)
        self.assertIn('[[ ! "$aws_version" =~ ^aws-cli/2\\. ]]', workflow)
        self.assertIn("needs: verify-environment", workflow)
        verify_permissions = workflow[verify_job:rotate_job]
        self.assertIn("permissions:\n      actions: read", verify_permissions)
        self.assertNotIn("contents: read", verify_permissions)
        self.assertIn("permissions: {}\n\njobs:", workflow)
        rotate_permissions = workflow[rotate_job:preflight]
        self.assertIn(
            "permissions:\n      contents: read\n      id-token: write",
            rotate_permissions,
        )
        self.assertIn("timeout-minutes: 12", rotate_permissions)
        self.assertIn("role-duration-seconds: 900", workflow)
        self.assertIn('"$GITHUB_REF" != "refs/heads/main"', workflow)
        self.assertIn(
            "RECOVERY_GENERATION: ${{ inputs.generation }}", verify_permissions
        )
        self.assertIn(
            '[[ ! "$RECOVERY_GENERATION" =~ ^[a-z0-9][a-z0-9-]{0,63}$ ]]',
            verify_permissions,
        )
        self.assertIn(
            'gh api "repos/${GITHUB_REPOSITORY}/environments/sandbox"', workflow
        )
        self.assertIn(".deployment_branch_policy.protected_branches == false", workflow)
        self.assertIn(
            ".deployment_branch_policy.custom_branch_policies == true", workflow
        )
        self.assertIn("/deployment-branch-policies?per_page=100", workflow)
        self.assertIn('.branch_policies[0].name == "main"', workflow)
        self.assertIn('.branch_policies[0].type == "branch"', workflow)
        self.assertIn('.type == "required_reviewers"', workflow)
        self.assertIn(".prevent_self_review == true", workflow)
        for name in (
            "QURL_SANDBOX_API_KEY",
            "QURL_SANDBOX_API_ENDPOINT",
            "QURL_SANDBOX_API_ENDPOINT_SHA256",
            "QURL_TUNNEL_RECOVERY_ROLE_ARN",
        ):
            self.assertIn(f"missing+=({name})", workflow)
            self.assertIn(f"${{{{ secrets.{name} }}}}", workflow)
        self.assertIn("^lv_live_[A-Za-z0-9_-]+$", workflow)
        self.assertIn(
            "^arn:aws:iam::[0-9]{12}:role/qurl-tunnel-enrollment-recovery-github-actions$",
            workflow,
        )
        self.assertIn("mask-aws-account-id: true", workflow)

    def test_validation_workflow_requires_tested_aws_cli_major(self) -> None:
        workflow = VALIDATE_WORKFLOW.read_text()
        self.assertIn("timeout-minutes: 10", workflow)
        require_cli = workflow.index("- name: Require tested AWS CLI major")
        contract_test = workflow.index("- name: Test sandbox enrollment recovery")
        self.assertLess(require_cli, contract_test)
        self.assertIn("if ! aws_version=$(aws --version 2>&1); then", workflow)
        self.assertIn("AWS CLI v2, but aws is unavailable", workflow)
        self.assertIn('[[ ! "$aws_version" =~ ^aws-cli/2\\. ]]', workflow)
        self.assertGreaterEqual(workflow.count("actions/setup-python@"), 1)
        self.assertIn('python-version: "3.13"', workflow)
        self.assertIn("pip install --require-hashes", workflow)
        self.assertIn("run: make lint-python", workflow)
        self.assertNotIn("ruff check --no-cache", workflow)
        self.assertIn(
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n"
            "        with:\n"
            "          persist-credentials: false",
            workflow,
        )
        self.assertIn("run: make test-python", workflow)
        self.assertNotIn("unittest discover", workflow)
        makefile = MAKEFILE.read_text()
        self.assertIn("lint-python:", makefile)
        self.assertIn("test-python:", makefile)
        self.assertIn(
            "PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "
            ".github/scripts/prepare_headless_enrollment_test.py",
            makefile,
        )
        self.assertIn("ruff check --no-cache $(PYTHON_LINT_FILES)", makefile)
        self.assertIn("ruff format --check --no-cache $(PYTHON_LINT_FILES)", makefile)
        self.assertIn(
            "PYTHON_LINT_FILES := .github/scripts/prepare-headless-enrollment.py "
            ".github/scripts/prepare_headless_enrollment_test.py",
            makefile,
        )
        requirements = (SCRIPT.parent / "requirements-lint.txt").read_text()
        self.assertRegex(
            requirements, r"ruff==0\.15\.8.*\\\n\s+--hash=sha256:[0-9a-f]{64}"
        )

    def test_every_target_has_a_distinct_parameter(self) -> None:
        parameters = [parameter for _slug, parameter in MODULE.TARGETS.values()]
        self.assertEqual(len(parameters), len(set(parameters)))

        allowlist = re.search(
            r"(?s)reviewedOperationalPaths := map\[string\]bool\{(.*?)\n\t\}",
            SANITIZER.read_text(),
        )
        self.assertIsNotNone(allowlist)
        reviewed = set(re.findall(r'"(/[^"]+)":\s+true', allowlist.group(1)))
        self.assertEqual(reviewed, set(parameters))

    def test_inputs_allow_only_reviewed_target_generation_and_region(self) -> None:
        MODULE.validate_inputs("fileviewer-nhp-replica-a", "attempt-1", "us-east-2")
        MODULE.validate_inputs("uploader-nhp-replica-b", "attempt-1", "us-east-2")
        MODULE.validate_inputs("detect-nhp-replica-a", "attempt-1", "us-east-2")
        MODULE.validate_inputs("watermark-nhp-replica-c", "attempt-1", "us-east-2")
        with self.assertRaisesRegex(MODULE.EnrollmentError, "target"):
            MODULE.validate_inputs("other-sandbox", "attempt-1", "us-east-2")
        with self.assertRaisesRegex(MODULE.EnrollmentError, "generation"):
            MODULE.validate_inputs("fileviewer-nhp-replica-a", "Attempt_1", "us-east-2")
        with self.assertRaisesRegex(MODULE.EnrollmentError, "us-east-2"):
            MODULE.validate_inputs("fileviewer-nhp-replica-a", "attempt-1", "us-west-2")

    def test_api_endpoint_requires_one_https_origin(self) -> None:
        endpoint = "https://api.example.com"
        endpoint_hash = MODULE.hashlib.sha256(endpoint.encode()).hexdigest()
        self.assertEqual(
            MODULE.validate_api_endpoint(endpoint + "/", expected_sha256=endpoint_hash),
            endpoint,
        )
        for value in (
            "http://api.example.com",
            "https://api.example.com/path",
            "https://api.example.com?next=elsewhere",
            "https://api.example.com#fragment",
            "https://api.example.com:443",
            "https://user@api.example.com",
        ):
            with self.subTest(value=value), self.assertRaises(MODULE.EnrollmentError):
                MODULE.validate_api_endpoint(value, expected_sha256=endpoint_hash)
        with self.assertRaisesRegex(MODULE.EnrollmentError, "reviewed origin"):
            MODULE.validate_api_endpoint(
                "https://other.example.com", expected_sha256=endpoint_hash
            )
        for value in (" " + endpoint, endpoint + "\n", "\t" + endpoint + "/"):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(
                    MODULE.EnrollmentError, "leading or trailing whitespace"
                ),
            ):
                MODULE.validate_api_endpoint(value, expected_sha256=endpoint_hash)

    def test_approved_endpoint_digest_shape_is_strict(self) -> None:
        self.assertIsNotNone(MODULE.SHA256_HEX.fullmatch("a" * 64))
        for value in ("A" * 64, "a" * 63, "a" * 65, "g" * 64):
            with self.subTest(value=value):
                self.assertIsNone(MODULE.SHA256_HEX.fullmatch(value))

    def test_api_request_keeps_authorization_on_reviewed_origin(self) -> None:
        response = FakeResponse(b'{"data":{"ok":true}}')
        with mock.patch.object(
            MODULE.NO_REDIRECT_OPENER, "open", return_value=response
        ) as open_request:
            self.assertEqual(
                MODULE.api_request(
                    "https://api.example.com", "lv_live_account-key", "/v1/resources"
                ),
                {"ok": True},
            )
        request = open_request.call_args.args[0]
        self.assertEqual(request.full_url, "https://api.example.com/v1/resources")
        self.assertEqual(
            request.get_header("Authorization"), "Bearer lv_live_account-key"
        )
        self.assertEqual(
            open_request.call_args.kwargs["timeout"], MODULE.API_TIMEOUT_SECONDS
        )
        self.assertIsNone(
            MODULE.NoRedirectHandler().redirect_request(
                request, None, 302, "Found", {}, "https://other.example.com"
            )
        )

    def test_api_opener_ignores_ambient_tls_and_proxy_overrides(self) -> None:
        with mock.patch.dict(
            MODULE.os.environ,
            {
                "SSL_CERT_FILE": "/tmp/untrusted-ca.pem",
                "SSL_CERT_DIR": "/tmp/untrusted-certs",
                "HTTPS_PROXY": "https://proxy.example.com",
            },
            clear=False,
        ):
            opener = MODULE.build_api_opener()
        self.assertFalse(
            any(
                isinstance(handler, MODULE.urllib.request.ProxyHandler)
                for handler in opener.handlers
            )
        )
        https_handler = next(
            handler
            for handler in opener.handlers
            if isinstance(handler, MODULE.urllib.request.HTTPSHandler)
        )
        self.assertEqual(https_handler._context.verify_mode, MODULE.ssl.CERT_REQUIRED)
        self.assertTrue(https_handler._context.check_hostname)

    def test_api_opener_fails_safely_without_compiled_trust_store(self) -> None:
        with (
            mock.patch.object(MODULE.os.path, "isfile", return_value=False),
            mock.patch.object(MODULE.os.path, "isdir", return_value=False),
            self.assertRaisesRegex(MODULE.EnrollmentError, "no compiled TLS trust"),
        ):
            MODULE.build_api_opener()

    def test_api_request_sends_exact_json_and_idempotency_headers(self) -> None:
        response = FakeResponse(b'{"data":{"ok":true}}', status=201)
        response_status: list[int] = []
        with mock.patch.object(
            MODULE.NO_REDIRECT_OPENER, "open", return_value=response
        ) as open_request:
            MODULE.api_request(
                "https://api.example.com",
                "lv_live_account-key",
                "/v1/api-keys",
                method="POST",
                body={"kind": "enrollment_token"},
                idempotency_key="headless-v2-attempt-1-target",
                expected_status=(200, 201),
                response_status=response_status,
            )
        request = open_request.call_args.args[0]
        self.assertEqual(
            request.get_header("Authorization"), "Bearer lv_live_account-key"
        )
        self.assertEqual(request.get_header("Content-type"), "application/json")
        self.assertEqual(
            request.get_header("Idempotency-key"), "headless-v2-attempt-1-target"
        )
        self.assertEqual(request.data, b'{"kind":"enrollment_token"}')
        self.assertEqual(response_status, [201])

    def test_api_request_rejects_large_or_unwrapped_responses(self) -> None:
        for body, message in (
            (b"x" * (MODULE.MAX_RESPONSE_BYTES + 1), "64 KiB"),
            (b"{}", "no data field"),
        ):
            with (
                self.subTest(message=message),
                mock.patch.object(
                    MODULE.NO_REDIRECT_OPENER, "open", return_value=FakeResponse(body)
                ),
            ):
                with self.assertRaisesRegex(MODULE.APIRequestOutcomeUnknown, message):
                    MODULE.api_request(
                        "https://api.example.com",
                        "lv_live_account-key",
                        "/v1/resources",
                    )

    def test_api_request_requires_exact_status_and_response_media_type(self) -> None:
        for response, message in (
            (
                FakeResponse(b'{"data":{}}', status=201),
                "returned HTTP 201 for the GET request; expected one of \\(200,\\)",
            ),
            (FakeResponse(b'{"data":{}}', content_types=[]), "Content-Type"),
            (
                FakeResponse(
                    b'{"data":{}}',
                    content_types=["application/json", "application/json"],
                ),
                "Content-Type",
            ),
        ):
            with (
                self.subTest(message=message),
                mock.patch.object(
                    MODULE.NO_REDIRECT_OPENER, "open", return_value=response
                ),
            ):
                with self.assertRaisesRegex(MODULE.APIRequestOutcomeUnknown, message):
                    MODULE.api_request(
                        "https://api.example.com",
                        "lv_live_account-key",
                        "/v1/resources",
                    )

    def test_api_request_accepts_json_media_type_parameters(self) -> None:
        for content_type in (
            "application/json; charset=utf-8",
            " Application/JSON ; Charset=UTF-8",
        ):
            with (
                self.subTest(content_type=content_type),
                mock.patch.object(
                    MODULE.NO_REDIRECT_OPENER,
                    "open",
                    return_value=FakeResponse(
                        b'{"data":{"ok":true}}', content_types=[content_type]
                    ),
                ),
            ):
                self.assertEqual(
                    MODULE.api_request(
                        "https://api.example.com",
                        "lv_live_account-key",
                        "/v1/resources",
                    ),
                    {"ok": True},
                )

    def test_api_request_normalizes_http_error_body_read_failure(self) -> None:
        class BrokenErrorBody:
            def read(self, _limit: int) -> bytes:
                raise MODULE.http.client.IncompleteRead(b"partial")

            def close(self) -> None:
                pass

        resource_id = "r_private-resource-id"
        rejected = MODULE.urllib.error.HTTPError(
            f"https://api.example.com/v1/resources/{resource_id}/sharing",
            403,
            "Forbidden",
            {},
            BrokenErrorBody(),
        )
        with mock.patch.object(MODULE.NO_REDIRECT_OPENER, "open", side_effect=rejected):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError, "rejected the GET request with HTTP 403"
            ) as raised:
                MODULE.api_request(
                    "https://api.example.com",
                    "lv_live_account-key",
                    f"/v1/resources/{resource_id}/sharing",
                )
        self.assertNotIn(resource_id, str(raised.exception))

    def test_api_request_distinguishes_unknown_from_retryable_rejection(
        self,
    ) -> None:
        for status in (307, 308, 408, 503):
            with self.subTest(status=status):
                error_body = mock.Mock()
                error_body.read.return_value = b""
                rejected = MODULE.urllib.error.HTTPError(
                    "https://api.example.com/v1/api-keys",
                    status,
                    "Retryable",
                    {},
                    error_body,
                )
                with mock.patch.object(
                    MODULE.NO_REDIRECT_OPENER, "open", side_effect=rejected
                ):
                    with self.assertRaisesRegex(
                        MODULE.APIRequestOutcomeUnknown,
                        f"rejected the POST request with HTTP {status}",
                    ):
                        MODULE.api_request(
                            "https://api.example.com",
                            "lv_live_account-key",
                            "/v1/api-keys",
                            method="POST",
                        )
        for status in (425, 429):
            with self.subTest(status=status):
                error_body = mock.Mock()
                error_body.read.return_value = b""
                rejected = MODULE.urllib.error.HTTPError(
                    "https://api.example.com/v1/api-keys",
                    status,
                    "Retryable",
                    {},
                    error_body,
                )
                with mock.patch.object(
                    MODULE.NO_REDIRECT_OPENER, "open", side_effect=rejected
                ):
                    with self.assertRaisesRegex(
                        MODULE.APIRequestRejectedRetryable,
                        f"rejected the POST request with HTTP {status}",
                    ):
                        MODULE.api_request(
                            "https://api.example.com",
                            "lv_live_account-key",
                            "/v1/api-keys",
                            method="POST",
                        )

    def test_api_request_preserves_bounded_retry_after_on_unknown_outcome(
        self,
    ) -> None:
        error_body = mock.Mock()
        error_body.read.return_value = b""
        rejected = MODULE.urllib.error.HTTPError(
            "https://api.example.com/v1/api-keys",
            429,
            "Rate limited",
            {"Retry-After": "17"},
            error_body,
        )
        with mock.patch.object(MODULE.NO_REDIRECT_OPENER, "open", side_effect=rejected):
            with self.assertRaises(MODULE.APIRequestRejectedRetryable) as raised:
                MODULE.api_request(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "/v1/api-keys",
                    method="POST",
                )
        self.assertEqual(raised.exception.retry_after_seconds, 17)

    def test_non_retryable_status_does_not_expose_retry_delay(self) -> None:
        for status in (403, 600):
            with self.subTest(status=status):
                error_body = mock.Mock()
                error_body.read.return_value = b""
                rejected = MODULE.urllib.error.HTTPError(
                    "https://api.example.com/v1/api-keys",
                    status,
                    "Rejected",
                    {"Retry-After": "17"},
                    error_body,
                )
                with mock.patch.object(
                    MODULE.NO_REDIRECT_OPENER, "open", side_effect=rejected
                ):
                    with self.assertRaises(MODULE.EnrollmentError) as raised:
                        MODULE.api_request(
                            "https://api.example.com",
                            "lv_live_account-key",
                            "/v1/api-keys",
                            method="POST",
                        )
                self.assertNotIsInstance(raised.exception, MODULE.APIRequestRetryable)

    def test_retry_after_parser_accepts_http_date_and_bounds_wait(self) -> None:
        now = dt.datetime(2026, 9, 4, 18, 0, tzinfo=dt.timezone.utc)
        self.assertEqual(MODULE.parse_retry_after("12", now=now), 12)
        self.assertEqual(MODULE.parse_retry_after("00000000005", now=now), 5)
        self.assertEqual(
            MODULE.parse_retry_after("999999999999999999999", now=now),
            MODULE.MAX_RETRY_AFTER_SECONDS,
        )
        self.assertEqual(
            MODULE.parse_retry_after("Fri, 04 Sep 2026 18:00:20 GMT", now=now),
            20,
        )
        self.assertEqual(
            MODULE.parse_retry_after("Fri, 04 Sep 2026 17:59:59 GMT", now=now),
            MODULE.RETRY_SECONDS,
        )
        self.assertEqual(MODULE.parse_retry_after("0", now=now), MODULE.RETRY_SECONDS)
        for value in (None, "", "1.5", "not-a-date"):
            with self.subTest(value=value):
                self.assertIsNone(MODULE.parse_retry_after(value, now=now))

    def test_api_request_normalizes_protocol_failure(self) -> None:
        with mock.patch.object(
            MODULE.NO_REDIRECT_OPENER,
            "open",
            side_effect=MODULE.http.client.BadStatusLine("not HTTP"),
        ):
            with self.assertRaisesRegex(
                MODULE.APIRequestOutcomeUnknown,
                "GET request failed",
            ):
                MODULE.api_request(
                    "https://api.example.com", "lv_live_account-key", "/v1/resources"
                )

    def test_expiry_rejects_naive_and_short_lived_values(self) -> None:
        now = dt.datetime(2026, 9, 4, 18, 0, tzinfo=dt.timezone.utc)
        with self.assertRaisesRegex(MODULE.EnrollmentError, "timezone"):
            MODULE.parse_expiry("2026-09-04T19:00:00", now=now)
        with self.assertRaisesRegex(MODULE.EnrollmentError, "new generation"):
            MODULE.parse_expiry("2026-09-04T18:44:59Z", now=now)
        MODULE.parse_expiry("2026-09-04T18:45:00Z", now=now)
        MODULE.parse_expiry("2026-09-04T19:05:00Z", now=now)
        with self.assertRaisesRegex(MODULE.EnrollmentError, "exceeds"):
            MODULE.parse_expiry("2026-09-04T19:05:01Z", now=now)

    def test_prepare_checks_contract_before_secret_write(self) -> None:
        resource_id = "MFkw-resource"
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": resource_id,
                }
            ],
            {"desired_state": "off", "serving_epoch": 0},
            {"desired_state": "on", "serving_epoch": 1},
            {"desired_state": "on", "serving_epoch": 1},
            {
                "kind": "enrollment_token",
                "key_id": "key_abc123def456",
                "target": "agent",
                "claims": [{"type": "connector", "id": "detect-sandbox"}],
                "api_key": "lv_live_test-token",
                "expires_at": VALID_EXPIRY,
            },
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch("builtins.print") as output,
        ):
            MODULE.prepare_enrollment(
                "https://api.example.com",
                "lv_live_account-key",
                "detect-nhp-replica-a",
                "attempt-1",
                "us-east-2",
                now=FIXED_NOW,
            )
        self.assertEqual(request.call_count, 5)
        self.assertEqual(
            request.call_args_list[2].kwargs["body"], {"desired_state": "on"}
        )
        self.assertEqual(
            request.call_args_list[2].kwargs["idempotency_key"],
            "headless-sharing-v2-attempt-1-detect-nhp-replica-a",
        )
        self.assertEqual(
            request.call_args_list[3].args[2], "/v1/resources/MFkw-resource/sharing"
        )
        self.assertEqual(
            request.call_args_list[4].kwargs["idempotency_key"],
            "headless-v2-attempt-1-detect-nhp-replica-a",
        )
        self.assertEqual(
            request.call_args_list[4].kwargs["expected_status"], (200, 201)
        )
        put.assert_called_once_with(
            "us-east-2",
            "/qurl-s3-connector/detect-nhp/replica-a/bootstrap",
            "lv_live_test-token",
        )
        self.assertEqual(
            {call.args[1] for call in request.call_args_list},
            {"lv_live_account-key"},
        )
        output.assert_has_calls(
            [
                mock.call(
                    "::notice::sharing for detect-nhp-replica-a changed from off to on during this run and was deliberately left on"
                ),
                mock.call(
                    "prepared one-hour enrollment for detect-nhp-replica-a at serving epoch 1; "
                    "expires 2026-09-04T19:00:00+00:00"
                ),
            ]
        )
        self.assertEqual(output.call_count, 2)

    def test_prepare_prints_possible_extra_credential_warning(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "on", "serving_epoch": 1},
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(
                MODULE,
                "mint_and_install_enrollment",
                return_value=(
                    FIXED_NOW + dt.timedelta(hours=1),
                    "installed credential key_abc123def456, but another may remain live",
                ),
            ),
            mock.patch("builtins.print") as output,
        ):
            MODULE.prepare_enrollment(
                "https://api.example.com",
                "lv_live_account-key",
                "detect-nhp-replica-a",
                "attempt-1",
                "us-east-2",
                now=FIXED_NOW,
            )
        output.assert_has_calls(
            [
                mock.call(
                    "::warning::installed credential key_abc123def456, but another may remain live",
                    file=MODULE.sys.stderr,
                ),
                mock.call(
                    "prepared one-hour enrollment for detect-nhp-replica-a at serving epoch 1; "
                    "expires 2026-09-04T19:00:00+00:00"
                ),
            ]
        )
        self.assertEqual(output.call_count, 2)

    def test_resource_resolution_guards_never_mint_or_write(self) -> None:
        cases = (
            ([], "exactly one resource"),
            (
                [
                    {
                        "slug": "detect-sandbox",
                        "type": "tunnel",
                        "status": "active",
                        "resource_id": "r_one",
                    },
                    {
                        "slug": "detect-sandbox",
                        "type": "tunnel",
                        "status": "active",
                        "resource_id": "r_two",
                    },
                ],
                "exactly one resource",
            ),
            (
                [
                    {
                        "slug": "detect-sandbox",
                        "type": "file",
                        "status": "active",
                        "resource_id": "r_one",
                    }
                ],
                "one active tunnel",
            ),
            (
                [
                    {
                        "slug": "detect-sandbox",
                        "type": "tunnel",
                        "status": "closed",
                        "resource_id": "r_one",
                    }
                ],
                "one active tunnel",
            ),
            (
                [{"slug": "detect-sandbox", "type": "tunnel", "status": "active"}],
                "no resource ID",
            ),
            (
                [
                    {
                        "slug": "detect-sandbox",
                        "type": "tunnel",
                        "status": "active",
                        "resource_id": 7,
                    }
                ],
                "no resource ID",
            ),
        )
        for resources, message in cases:
            with (
                self.subTest(resources=resources),
                mock.patch.object(
                    MODULE, "api_request", return_value=resources
                ) as request,
                mock.patch.object(MODULE, "put_parameter") as put,
            ):
                with self.assertRaisesRegex(MODULE.EnrollmentError, message):
                    MODULE.prepare_enrollment(
                        "https://api.example.com",
                        "lv_live_account-key",
                        "detect-nhp-replica-a",
                        "attempt-1",
                        "us-east-2",
                    )
                self.assertEqual(request.call_count, 1)
                put.assert_not_called()

    def test_claim_mismatch_never_writes_secret(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "on", "serving_epoch": 1},
            {
                "kind": "enrollment_token",
                "key_id": "key_abc123def456",
                "target": "agent",
                "claims": [{"type": "connector", "id": "other"}],
                "api_key": "lv_live_test-token",
                "expires_at": VALID_EXPIRY,
            },
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "credential key_abc123def456 was minted but not installed",
            ):
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        put.assert_not_called()

    def test_mint_lost_response_retries_same_operation_and_accepts_replay(self) -> None:
        credential = {
            "kind": "enrollment_token",
            "key_id": "key_abc123def456",
            "target": "agent",
            "claims": [{"type": "connector", "id": "detect-sandbox"}],
            "api_key": "lv_live_test-token",
            "expires_at": VALID_EXPIRY,
        }
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "r_one",
                }
            ],
            {"desired_state": "on", "serving_epoch": 1},
            MODULE.APIRequestOutcomeUnknown("response lost"),
            credential,
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            MODULE.prepare_enrollment(
                "https://api.example.com",
                "lv_live_account-key",
                "detect-nhp-replica-a",
                "attempt-1",
                "us-east-2",
                now=FIXED_NOW,
            )
        first_mint = request.call_args_list[2]
        replay_mint = request.call_args_list[3]
        self.assertEqual(first_mint, replay_mint)
        self.assertEqual(first_mint.kwargs["expected_status"], (200, 201))
        sleep.assert_called_once_with(MODULE.RETRY_SECONDS)
        put.assert_called_once()

    def test_new_mint_after_unknown_outcome_reports_possible_live_credential(
        self,
    ) -> None:
        credential = {
            "kind": "enrollment_token",
            "key_id": "key_abc123def456",
            "target": "agent",
            "claims": [{"type": "connector", "id": "detect-sandbox"}],
            "api_key": "lv_live_test-token",
            "expires_at": VALID_EXPIRY,
        }
        attempts: list[object] = [
            MODULE.APIRequestOutcomeUnknown("response lost"),
            credential,
        ]

        def request(*_args: object, **kwargs: object) -> object:
            result = attempts.pop(0)
            if isinstance(result, Exception):
                raise result
            response_status = kwargs["response_status"]
            assert isinstance(response_status, list)
            response_status[:] = [201]
            return result

        with (
            mock.patch.object(MODULE, "api_request", side_effect=request),
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep"),
        ):
            expiry, warning = MODULE.mint_and_install_enrollment(
                "https://api.example.com",
                "lv_live_account-key",
                "detect-nhp-replica-a",
                "attempt-1",
                "us-east-2",
                "detect-sandbox",
                "/reviewed/name",
                now=FIXED_NOW,
            )
        self.assertEqual(expiry.isoformat(), "2026-09-04T19:00:00+00:00")
        self.assertIn("installed credential key_abc123def456", warning)
        self.assertIn("another one-hour credential may remain live", warning)
        put.assert_called_once()

    def test_mint_retry_honors_server_delay_with_hard_cap(self) -> None:
        credential = {
            "kind": "enrollment_token",
            "target": "agent",
            "claims": [{"type": "connector", "id": "detect-sandbox"}],
            "api_key": "lv_live_test-token",
            "expires_at": VALID_EXPIRY,
        }
        for retry_after, expected_delay in (
            (9, 9),
            (MODULE.MAX_RETRY_AFTER_SECONDS + 100, 30),
            (-5, 0),
        ):
            responses = [
                [
                    {
                        "slug": "detect-sandbox",
                        "type": "tunnel",
                        "status": "active",
                        "resource_id": "r_one",
                    }
                ],
                {"desired_state": "on", "serving_epoch": 1},
                MODULE.APIRequestOutcomeUnknown(
                    "retryable failure", retry_after_seconds=retry_after
                ),
                credential,
            ]
            with (
                self.subTest(retry_after=retry_after),
                mock.patch.object(MODULE, "api_request", side_effect=responses),
                mock.patch.object(MODULE, "put_parameter"),
                mock.patch.object(MODULE.time, "sleep") as sleep,
            ):
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
            sleep.assert_called_once_with(expected_delay)

    def test_mint_double_failure_is_recoverable_without_secret_output(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "r_one",
                }
            ],
            {"desired_state": "on", "serving_epoch": 1},
            MODULE.APIRequestOutcomeUnknown("first failure with lv_live_secret-token"),
            MODULE.APIRequestOutcomeUnknown("second failure with lv_live_secret-token"),
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError, "retry the same target and generation"
            ) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertNotIn("lv_live_secret-token", str(raised.exception))
        sleep.assert_called_once_with(MODULE.RETRY_SECONDS)
        put.assert_not_called()

    def test_mint_hard_rejection_after_unknown_keeps_recovery_warning(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "r_one",
                }
            ],
            {"desired_state": "on", "serving_epoch": 1},
            MODULE.APIRequestOutcomeUnknown("first response was lost"),
            MODULE.EnrollmentError("qURL API rejected the POST request with HTTP 403"),
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep"),
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError, "retry the same target and generation"
            ) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertIn("HTTP 403", str(raised.exception.__cause__))
        put.assert_not_called()

    def test_mint_rejection_is_not_retried_or_called_unknown(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "r_one",
                }
            ],
            {"desired_state": "on", "serving_epoch": 1},
            MODULE.EnrollmentError("qURL API rejected POST /v1/api-keys with HTTP 403"),
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError, "rejected POST /v1/api-keys with HTTP 403"
            ) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertEqual(request.call_count, 3)
        self.assertNotIn("unknown", str(raised.exception))
        put.assert_not_called()

    def test_mint_retryable_rejection_is_bounded_and_not_called_unknown(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "r_one",
                }
            ],
            {"desired_state": "on", "serving_epoch": 1},
            MODULE.APIRequestRejectedRetryable("HTTP 429"),
            MODULE.APIRequestRejectedRetryable("HTTP 429"),
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError, "rejected after one bounded retry"
            ) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertEqual(request.call_count, 4)
        self.assertNotIn("unknown", str(raised.exception))
        sleep.assert_called_once_with(MODULE.RETRY_SECONDS)
        put.assert_not_called()

    def test_later_failure_reports_observed_sharing_transition(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "r_one",
                }
            ],
            {"desired_state": "off", "serving_epoch": 3},
            {"desired_state": "on", "serving_epoch": 4},
            {"desired_state": "on", "serving_epoch": 4},
            MODULE.EnrollmentError("qURL API rejected the POST request with HTTP 403"),
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "sharing changed from off to on during this run; sharing was left on",
            ) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertIsInstance(raised.exception.__cause__, MODULE.EnrollmentError)
        self.assertIn("HTTP 403", str(raised.exception.__cause__))
        put.assert_not_called()

    def test_existing_sharing_state_does_not_claim_this_run_enabled_it(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "r_one",
                }
            ],
            {"desired_state": "on", "serving_epoch": 4},
            MODULE.EnrollmentError("qURL API rejected the POST request with HTTP 403"),
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
        ):
            with self.assertRaises(MODULE.EnrollmentError) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertNotIn("sharing was left on", str(raised.exception))
        put.assert_not_called()

    def test_malformed_token_and_expiry_report_safe_credential_id(self) -> None:
        base = {
            "kind": "enrollment_token",
            "key_id": "key_abcdefghijklmnop",
            "target": "agent",
            "claims": [{"type": "connector", "id": "detect-sandbox"}],
            "api_key": "lv_live_valid-token",
            "expires_at": VALID_EXPIRY,
        }
        for override in ({"api_key": "bad"}, {"expires_at": 7}):
            credential = {**base, **override}
            responses = [
                [
                    {
                        "slug": "detect-sandbox",
                        "type": "tunnel",
                        "status": "active",
                        "resource_id": "r_one",
                    }
                ],
                {"desired_state": "on", "serving_epoch": 1},
                credential,
            ]
            with (
                self.subTest(override=override),
                mock.patch.object(MODULE, "api_request", side_effect=responses),
                mock.patch.object(MODULE, "put_parameter") as put,
            ):
                with self.assertRaisesRegex(
                    MODULE.EnrollmentError,
                    "credential key_abcdefghijklmnop was minted but not installed",
                ):
                    MODULE.prepare_enrollment(
                        "https://api.example.com",
                        "lv_live_account-key",
                        "detect-nhp-replica-a",
                        "attempt-1",
                        "us-east-2",
                        now=FIXED_NOW,
                    )
                put.assert_not_called()

    def test_malformed_response_without_safe_id_reports_live_credential(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "r_one",
                }
            ],
            {"desired_state": "on", "serving_epoch": 1},
            {
                "kind": "enrollment_token",
                "key_id": "unsafe/private-id",
                "target": "agent",
                "claims": [{"type": "connector", "id": "other"}],
                "api_key": "lv_live_valid-token",
                "expires_at": VALID_EXPIRY,
            },
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "credential was minted but not installed.*ID is unavailable",
            ) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertNotIn("unsafe/private-id", str(raised.exception))
        self.assertIsInstance(raised.exception.__cause__, MODULE.EnrollmentError)
        put.assert_not_called()

    def test_ssm_failure_reports_safe_credential_id_and_preserves_cause(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "r_one",
                }
            ],
            {"desired_state": "on", "serving_epoch": 1},
            {
                "kind": "enrollment_token",
                "key_id": "key_abc123def456",
                "target": "agent",
                "claims": [{"type": "connector", "id": "detect-sandbox"}],
                "api_key": "lv_live_valid-token",
                "expires_at": VALID_EXPIRY,
            },
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(
                MODULE,
                "put_parameter",
                side_effect=MODULE.EnrollmentError("AWS rejected write"),
            ),
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "credential key_abc123def456 was minted but not installed",
            ) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertIsInstance(raised.exception.__cause__, MODULE.EnrollmentError)
        self.assertNotIn("lv_live_valid-token", str(raised.exception))
        self.assertIn(
            "only while the recovered token has at least 45 minutes",
            str(raised.exception),
        )
        self.assertIn("otherwise use a new generation", str(raised.exception))

    def test_ssm_timeout_reports_unknown_installation_outcome(self) -> None:
        responses = [
            {
                "kind": "enrollment_token",
                "key_id": "key_abc123def456",
                "target": "agent",
                "claims": [{"type": "connector", "id": "detect-sandbox"}],
                "api_key": "lv_live_valid-token",
                "expires_at": VALID_EXPIRY,
            }
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(
                MODULE.subprocess,
                "run",
                side_effect=MODULE.subprocess.TimeoutExpired("aws", 30),
            ),
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "credential key_abc123def456 was minted, but its installation outcome is unknown",
            ) as raised:
                MODULE.mint_and_install_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    "detect-sandbox",
                    "/reviewed/name",
                    now=FIXED_NOW,
                )
        self.assertIsInstance(
            raised.exception.__cause__, MODULE.EnrollmentParameterOutcomeUnknown
        )
        self.assertNotIn("was minted but not installed", str(raised.exception))
        self.assertNotIn("lv_live_valid-token", str(raised.exception))
        self.assertIn("repeat the idempotent parameter write", str(raised.exception))

    def test_ssm_timeout_without_safe_id_preserves_unknown_outcome(self) -> None:
        responses = [
            {
                "kind": "enrollment_token",
                "key_id": "unsafe/private-id",
                "target": "agent",
                "claims": [{"type": "connector", "id": "detect-sandbox"}],
                "api_key": "lv_live_valid-token",
                "expires_at": VALID_EXPIRY,
            }
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(
                MODULE.subprocess,
                "run",
                side_effect=MODULE.subprocess.TimeoutExpired("aws", 30),
            ),
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "installation outcome is unknown.*credential ID is unavailable",
            ) as raised:
                MODULE.mint_and_install_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    "detect-sandbox",
                    "/reviewed/name",
                    now=FIXED_NOW,
                )
        self.assertIsInstance(
            raised.exception.__cause__, MODULE.EnrollmentParameterOutcomeUnknown
        )
        self.assertNotIn("unsafe/private-id", str(raised.exception))
        self.assertNotIn("lv_live_valid-token", str(raised.exception))
        self.assertIn("do not assume the parameter is unchanged", str(raised.exception))

    def test_invalid_on_zero_state_never_mints_or_writes(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "on", "serving_epoch": 0},
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError, "positive serving epoch"
            ):
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                )
        self.assertEqual(request.call_count, 2)
        put.assert_not_called()

    def test_existing_positive_epoch_can_rotate_without_lifecycle_change(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "on", "serving_epoch": 3},
            {
                "kind": "enrollment_token",
                "target": "agent",
                "claims": [{"type": "connector", "id": "detect-sandbox"}],
                "api_key": "lv_live_test-token",
                "expires_at": VALID_EXPIRY,
            },
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
        ):
            MODULE.prepare_enrollment(
                "https://api.example.com",
                "lv_live_account-key",
                "detect-nhp-replica-a",
                "attempt-2",
                "us-east-2",
                now=FIXED_NOW,
            )
        self.assertEqual(request.call_count, 3)
        self.assertEqual(request.call_args_list[2].args[2], "/v1/api-keys")
        self.assertEqual(
            request.call_args_list[2].kwargs["idempotency_key"],
            "headless-v2-attempt-2-detect-nhp-replica-a",
        )
        put.assert_called_once()

    def test_lost_put_response_recovers_from_committed_state(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 0},
            MODULE.APIRequestOutcomeUnknown("qURL API PUT request failed"),
            {"desired_state": "on", "serving_epoch": 1},
            {
                "kind": "enrollment_token",
                "target": "agent",
                "claims": [{"type": "connector", "id": "detect-sandbox"}],
                "api_key": "lv_live_test-token",
                "expires_at": VALID_EXPIRY,
            },
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
        ):
            MODULE.prepare_enrollment(
                "https://api.example.com",
                "lv_live_account-key",
                "detect-nhp-replica-a",
                "attempt-1",
                "us-east-2",
                now=FIXED_NOW,
            )
        put.assert_called_once()

    def test_deterministic_put_rejection_fails_without_polling(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 0},
            MODULE.EnrollmentError("qURL API rejected the PUT request with HTTP 403"),
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(MODULE.EnrollmentError, "HTTP 403") as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertEqual(request.call_count, 3)
        self.assertNotIn("may have been applied", str(raised.exception))
        sleep.assert_not_called()
        put.assert_not_called()

    def test_retryable_put_rejection_retries_once_and_confirms_epoch(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 0},
            MODULE.APIRequestRejectedRetryable("HTTP 429", retry_after_seconds=17),
            {"desired_state": "on", "serving_epoch": 1},
            {"desired_state": "on", "serving_epoch": 1},
            {
                "kind": "enrollment_token",
                "target": "agent",
                "claims": [{"type": "connector", "id": "detect-sandbox"}],
                "api_key": "lv_live_test-token",
                "expires_at": VALID_EXPIRY,
            },
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            MODULE.prepare_enrollment(
                "https://api.example.com",
                "lv_live_account-key",
                "detect-nhp-replica-a",
                "attempt-1",
                "us-east-2",
                now=FIXED_NOW,
            )
        self.assertEqual(request.call_count, 6)
        self.assertEqual(request.call_args_list[2], request.call_args_list[3])
        sleep.assert_called_once_with(17)
        put.assert_called_once()

    def test_retryable_put_rejection_stops_after_one_retry_without_polling(
        self,
    ) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 0},
            MODULE.APIRequestRejectedRetryable("HTTP 429"),
            MODULE.APIRequestRejectedRetryable("HTTP 429"),
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError, "rejected after one bounded retry"
            ) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertEqual(request.call_count, 4)
        self.assertNotIn("may have been applied", str(raised.exception))
        sleep.assert_called_once_with(MODULE.RETRY_SECONDS)
        put.assert_not_called()

    def test_lost_put_and_poll_responses_warn_that_sharing_may_be_on(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 0},
            MODULE.APIRequestOutcomeUnknown("qURL API PUT request failed"),
            *[MODULE.APIRequestOutcomeUnknown("temporary status failure")]
            * MODULE.SHARING_POLL_ATTEMPTS,
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep"),
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "sharing may have been applied before the response was lost and may have been left on",
            ):
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        put.assert_not_called()

    def test_transient_poll_failure_uses_remaining_attempts(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 3},
            {"desired_state": "on", "serving_epoch": 4},
            MODULE.APIRequestOutcomeUnknown("temporary status failure"),
            {"desired_state": "on", "serving_epoch": 4},
            {
                "kind": "enrollment_token",
                "target": "agent",
                "claims": [{"type": "connector", "id": "detect-sandbox"}],
                "api_key": "lv_live_test-token",
                "expires_at": VALID_EXPIRY,
            },
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            MODULE.prepare_enrollment(
                "https://api.example.com",
                "lv_live_account-key",
                "detect-nhp-replica-a",
                "attempt-3",
                "us-east-2",
                now=FIXED_NOW,
            )
        sleep.assert_called_once_with(MODULE.SHARING_POLL_SECONDS)
        put.assert_called_once()

    def test_rate_limited_poll_honors_retry_after_and_continues(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 3},
            {"desired_state": "on", "serving_epoch": 4},
            MODULE.APIRequestRejectedRetryable("HTTP 429", retry_after_seconds=17),
            {"desired_state": "on", "serving_epoch": 4},
            {
                "kind": "enrollment_token",
                "target": "agent",
                "claims": [{"type": "connector", "id": "detect-sandbox"}],
                "api_key": "lv_live_test-token",
                "expires_at": VALID_EXPIRY,
            },
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            MODULE.prepare_enrollment(
                "https://api.example.com",
                "lv_live_account-key",
                "detect-nhp-replica-a",
                "attempt-3",
                "us-east-2",
                now=FIXED_NOW,
            )
        sleep.assert_called_once_with(17)
        put.assert_called_once()

    def test_clean_off_polls_clear_unknown_put_warning(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 0},
            MODULE.APIRequestOutcomeUnknown("qURL API PUT response was lost"),
            *[{"desired_state": "off", "serving_epoch": 0}]
            * MODULE.SHARING_POLL_ATTEMPTS,
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep"),
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "sharing did not reach the required serving epoch",
            ) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertNotIn("may have been", str(raised.exception))
        self.assertNotIn("left on", str(raised.exception))
        put.assert_not_called()

    def test_sharing_poll_allows_propagation_before_operator_retry(self) -> None:
        self.assertGreaterEqual(
            (MODULE.SHARING_POLL_ATTEMPTS - 1) * MODULE.SHARING_POLL_SECONDS,
            50,
        )

    def test_stale_epoch_observed_on_reports_left_on(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 1},
            MODULE.APIRequestOutcomeUnknown("qURL API PUT response was lost"),
            *[{"desired_state": "on", "serving_epoch": 1}]
            * MODULE.SHARING_POLL_ATTEMPTS,
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep"),
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "sharing for this resource was observed on and was left on",
            ):
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        put.assert_not_called()

    def test_successful_retry_reports_definite_sharing_state(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 0},
            MODULE.APIRequestOutcomeUnknown(
                "qURL API PUT response was lost", retry_after_seconds=0
            ),
            {"desired_state": "on", "serving_epoch": 1},
            *[MODULE.APIRequestOutcomeUnknown("temporary status failure")]
            * MODULE.SHARING_POLL_ATTEMPTS,
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep"),
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "sharing changed from off to on during this run and was left on",
            ) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertNotIn("may have been applied", str(raised.exception))
        put.assert_not_called()

    def test_deterministic_poll_rejection_fails_without_retry(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 0},
            {"desired_state": "on", "serving_epoch": 1},
            MODULE.EnrollmentError("qURL API rejected the GET request with HTTP 403"),
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "sharing status check was rejected.*sharing was left on",
            ) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertEqual(request.call_count, 4)
        self.assertIsInstance(raised.exception.__cause__, MODULE.EnrollmentError)
        self.assertIn("HTTP 403", str(raised.exception.__cause__))
        sleep.assert_not_called()
        put.assert_not_called()

    def test_deterministic_poll_rejection_preserves_unknown_put_warning(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 0},
            MODULE.APIRequestOutcomeUnknown("qURL API PUT request failed"),
            MODULE.EnrollmentError("qURL API rejected the GET request with HTTP 403"),
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "sharing update outcome became unknown.*may have been left on",
            ) as raised:
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        self.assertEqual(request.call_count, 4)
        self.assertIsInstance(raised.exception.__cause__, MODULE.EnrollmentError)
        self.assertIn("HTTP 403", str(raised.exception.__cause__))
        sleep.assert_not_called()
        put.assert_not_called()

    def test_unadvanced_epoch_never_writes_secret(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 0},
            {"desired_state": "on", "serving_epoch": 0},
            *[{"desired_state": "on", "serving_epoch": 0}]
            * MODULE.SHARING_POLL_ATTEMPTS,
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep"),
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError, "required serving epoch"
            ):
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        put.assert_not_called()

    def test_poll_failure_reports_successful_sharing_update(self) -> None:
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "off", "serving_epoch": 0},
            {"desired_state": "on", "serving_epoch": 1},
            *[MODULE.APIRequestOutcomeUnknown("temporary status failure")]
            * MODULE.SHARING_POLL_ATTEMPTS,
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses),
            mock.patch.object(MODULE, "put_parameter") as put,
            mock.patch.object(MODULE.time, "sleep"),
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError,
                "sharing changed from off to on during this run and was left on",
            ):
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    "detect-nhp-replica-a",
                    "attempt-1",
                    "us-east-2",
                    now=FIXED_NOW,
                )
        put.assert_not_called()

    def test_error_formatter_surfaces_only_enrollment_error_causes(self) -> None:
        raw = ValueError("raw failure with lv_live_secret-token")
        detail = MODULE.APIRequestOutcomeUnknown(
            "qURL API rejected the POST request with HTTP 429"
        )
        detail.__cause__ = raw
        top = MODULE.EnrollmentError("enrollment credential result is unknown")
        top.__cause__ = detail

        rendered = MODULE.format_enrollment_error(top)

        self.assertEqual(
            rendered,
            "enrollment credential result is unknown "
            "(caused by: qURL API rejected the POST request with HTTP 429)",
        )
        self.assertNotIn("lv_live_secret-token", rendered)

    def test_run_suppresses_unexpected_exception_details(self) -> None:
        with (
            mock.patch.object(
                MODULE,
                "main",
                side_effect=ValueError("raw failure with lv_live_secret-token"),
            ),
            mock.patch("builtins.print") as output,
        ):
            with self.assertRaisesRegex(SystemExit, "1"):
                MODULE.run()
        output.assert_called_once_with(
            "error: unexpected internal failure (ValueError)", file=MODULE.sys.stderr
        )

    def test_put_parameter_sends_token_only_on_stdin(self) -> None:
        clean_env = {
            "PATH": "/bin",
            "QURL_SANDBOX_API_KEY": "lv_live_account-key",
            "QURL_SANDBOX_API_ENDPOINT": "https://api.example.com",
            "QURL_SANDBOX_API_ENDPOINT_SHA256": "a" * 64,
            "AWS_PROFILE": "ambient-profile",
            "AWS_DEFAULT_PROFILE": "ambient-default-profile",
            "AWS_DEFAULT_OUTPUT": "yaml",
            "AWS_ENDPOINT_URL": "https://private.example.com",
            "AWS_ENDPOINT_URL_SSM": "https://private.example.com/ssm",
            "AWS_ENDPOINT_URL_STS": "https://private.example.com/sts",
            "AWS_CA_BUNDLE": "/tmp/private-ca.pem",
            "AWS_DATA_PATH": "/tmp/private-service-models",
            "AWS_CONTAINER_CREDENTIALS_FULL_URI": "https://private.example.com/credentials",
            "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI": "/private-credentials",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN": "private-authorization-token",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE": "/tmp/private-authorization-token",
            "AWS_WEB_IDENTITY_TOKEN_FILE": "/tmp/private-web-identity-token",
            "AWS_ROLE_ARN": "arn:aws:iam::" + "111111" + "111111:role/private-role",
            "AWS_ROLE_SESSION_NAME": "private-role-session",
            "BOTO_CONFIG": "/tmp/private-boto-config",
            "HTTP_PROXY": "http://proxy.example.com",
            "HTTPS_PROXY": "https://proxy.example.com",
            "NO_PROXY": "localhost",
            "ALL_PROXY": "socks5://proxy.example.com",
            "http_proxy": "http://lower-proxy.example.com",
            "https_proxy": "https://lower-proxy.example.com",
            "no_proxy": "127.0.0.1",
            "all_proxy": "socks5://lower-proxy.example.com",
            "AWS_CLI_FILE_ENCODING": "utf-16",
            "AWS_RETRY_MODE": "adaptive",
            "AWS_MAX_ATTEMPTS": "99",
            "AWS_USE_FIPS_ENDPOINT": "true",
            "AWS_USE_DUALSTACK_ENDPOINT": "true",
            "AWS_CLI_AUTO_PROMPT": "on",
            "AWS_CONFIG_FILE": "/tmp/private-config",
            "AWS_SHARED_CREDENTIALS_FILE": "/tmp/private-credentials",
            "AWS_PAGER": "unsafe-pager",
        }
        completed = mock.Mock(returncode=0)
        with (
            mock.patch.dict(MODULE.os.environ, clean_env, clear=True),
            mock.patch.object(MODULE.subprocess, "run", return_value=completed) as run,
        ):
            MODULE.put_parameter("us-east-2", "/reviewed/name", "lv_live_secret-token")
        args = run.call_args.args[0]
        kwargs = run.call_args.kwargs
        self.assertNotIn("lv_live_secret-token", " ".join(args))
        self.assertNotIn("lv_live_secret-token", " ".join(kwargs["env"].values()))
        self.assertNotIn("QURL_SANDBOX_API_KEY", kwargs["env"])
        self.assertNotIn("QURL_SANDBOX_API_ENDPOINT", kwargs["env"])
        self.assertNotIn("QURL_SANDBOX_API_ENDPOINT_SHA256", kwargs["env"])
        self.assertNotIn("AWS_PROFILE", kwargs["env"])
        self.assertNotIn("AWS_DEFAULT_PROFILE", kwargs["env"])
        self.assertNotIn("AWS_DEFAULT_OUTPUT", kwargs["env"])
        self.assertNotIn("AWS_ENDPOINT_URL", kwargs["env"])
        self.assertNotIn("AWS_ENDPOINT_URL_SSM", kwargs["env"])
        self.assertNotIn("AWS_ENDPOINT_URL_STS", kwargs["env"])
        self.assertNotIn("AWS_CA_BUNDLE", kwargs["env"])
        self.assertNotIn("AWS_DATA_PATH", kwargs["env"])
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
            self.assertNotIn(credential_variable, kwargs["env"])
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
            self.assertNotIn(proxy_variable, kwargs["env"])
        self.assertEqual(kwargs["env"]["AWS_CONFIG_FILE"], MODULE.os.devnull)
        self.assertEqual(
            kwargs["env"]["AWS_SHARED_CREDENTIALS_FILE"], MODULE.os.devnull
        )
        self.assertEqual(kwargs["env"]["AWS_CLI_FILE_ENCODING"], "utf-8")
        self.assertEqual(kwargs["env"]["AWS_RETRY_MODE"], "standard")
        self.assertEqual(kwargs["env"]["AWS_MAX_ATTEMPTS"], "1")
        self.assertEqual(kwargs["env"]["AWS_USE_FIPS_ENDPOINT"], "false")
        self.assertEqual(kwargs["env"]["AWS_USE_DUALSTACK_ENDPOINT"], "false")
        self.assertEqual(kwargs["env"]["AWS_EC2_METADATA_DISABLED"], "true")
        self.assertEqual(kwargs["env"]["AWS_CLI_AUTO_PROMPT"], "off")
        self.assertEqual(kwargs["env"]["AWS_PAGER"], "")
        self.assertEqual(kwargs["input"], "lv_live_secret-token")
        self.assertEqual(args[args.index("--value") + 1], "file:///dev/stdin")
        self.assertEqual(args[args.index("--name") + 1], "/reviewed/name")
        self.assertEqual(args[args.index("--region") + 1], "us-east-2")
        self.assertEqual(args[args.index("--type") + 1], "SecureString")
        self.assertIn("--overwrite", args)
        self.assertEqual(kwargs["timeout"], MODULE.AWS_TIMEOUT_SECONDS)

    def test_aws_cli_expands_stdin_for_ssm_value(self) -> None:
        if not shutil.which("aws"):
            if MODULE.os.environ.get("CI"):
                self.fail(
                    "AWS CLI is required for the CI stdin parameter expansion contract"
                )
            self.skipTest("AWS CLI is not installed")
        captured: list[bytes] = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                captured.append(self.rfile.read(int(self.headers["Content-Length"])))
                response = b'{"Version":1}'
                self.send_response(200)
                self.send_header("Content-Type", "application/x-amz-json-1.1")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)

            def log_message(self, *_args: object) -> None:
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        server.timeout = 15
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        clean_env = {
            "PATH": MODULE.os.environ.get("PATH", ""),
            "AWS_ACCESS_KEY_ID": "dummy",
            "AWS_SECRET_ACCESS_KEY": "dummy",
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_CONFIG_FILE": MODULE.os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": MODULE.os.devnull,
            "NO_PROXY": "127.0.0.1",
        }
        try:
            result = MODULE.subprocess.run(
                [
                    *MODULE._put_parameter_command("us-east-2", "/tmp/probe"),
                    "--endpoint-url",
                    f"http://127.0.0.1:{server.server_port}",
                ],
                input="probe-value",
                text=True,
                stdout=MODULE.subprocess.PIPE,
                stderr=MODULE.subprocess.PIPE,
                env=clean_env,
                timeout=20,
            )
        finally:
            server.server_close()
            thread.join(timeout=16)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(thread.is_alive())
        self.assertEqual(
            len(captured), 1, "AWS CLI did not send exactly one SSM request"
        )
        self.assertEqual(
            MODULE.json.loads(captured[0]),
            {
                "Name": "/tmp/probe",
                "Value": "probe-value",
                "Type": "SecureString",
                "Overwrite": True,
            },
        )

    def test_main_pops_api_key_before_preparation(self) -> None:
        argv = [
            "prepare-headless-enrollment.py",
            "--target",
            "detect-nhp-replica-a",
            "--generation",
            "attempt-1",
            "--region",
            "us-east-2",
        ]
        with (
            mock.patch.object(MODULE.sys, "argv", argv),
            mock.patch.dict(
                MODULE.os.environ,
                {
                    "QURL_SANDBOX_API_KEY": "lv_live_account-key",
                    "QURL_SANDBOX_API_ENDPOINT": "https://api.example.com",
                    "QURL_SANDBOX_API_ENDPOINT_SHA256": MODULE.hashlib.sha256(
                        b"https://api.example.com"
                    ).hexdigest(),
                },
                clear=True,
            ),
            mock.patch.object(MODULE, "prepare_enrollment") as prepare,
        ):
            MODULE.main()
            self.assertNotIn("QURL_SANDBOX_API_KEY", MODULE.os.environ)
            self.assertNotIn("QURL_SANDBOX_API_ENDPOINT", MODULE.os.environ)
            self.assertNotIn("QURL_SANDBOX_API_ENDPOINT_SHA256", MODULE.os.environ)
        prepare.assert_called_once_with(
            "https://api.example.com",
            "lv_live_account-key",
            "detect-nhp-replica-a",
            "attempt-1",
            "us-east-2",
        )

    def test_main_rejects_bad_api_key_before_request(self) -> None:
        argv = [
            "prepare-headless-enrollment.py",
            "--target",
            "detect-nhp-replica-a",
            "--generation",
            "attempt-1",
            "--region",
            "us-east-2",
        ]
        with (
            mock.patch.object(MODULE.sys, "argv", argv),
            mock.patch.dict(
                MODULE.os.environ,
                {
                    "QURL_SANDBOX_API_KEY": "bad",
                    "QURL_SANDBOX_API_ENDPOINT": "https://api.example.com",
                    "QURL_SANDBOX_API_ENDPOINT_SHA256": MODULE.hashlib.sha256(
                        b"https://api.example.com"
                    ).hexdigest(),
                },
                clear=True,
            ),
            mock.patch.object(MODULE, "validate_api_endpoint") as validate_endpoint,
            mock.patch.object(MODULE, "prepare_enrollment") as prepare,
        ):
            with self.assertRaisesRegex(MODULE.EnrollmentError, "missing or malformed"):
                MODULE.main()
        validate_endpoint.assert_not_called()
        prepare.assert_not_called()

    def test_main_rejects_missing_endpoint_digest_before_request(self) -> None:
        argv = [
            "prepare-headless-enrollment.py",
            "--target",
            "detect-nhp-replica-a",
            "--generation",
            "attempt-1",
            "--region",
            "us-east-2",
        ]
        with (
            mock.patch.object(MODULE.sys, "argv", argv),
            mock.patch.dict(
                MODULE.os.environ,
                {
                    "QURL_SANDBOX_API_KEY": "lv_live_account-key",
                    "QURL_SANDBOX_API_ENDPOINT": "https://api.example.com",
                },
                clear=True,
            ),
            mock.patch.object(MODULE, "validate_api_endpoint") as validate_endpoint,
            mock.patch.object(MODULE, "prepare_enrollment") as prepare,
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentError, "API_ENDPOINT_SHA256 is missing or malformed"
            ):
                MODULE.main()
        validate_endpoint.assert_not_called()
        prepare.assert_not_called()

    def test_put_parameter_reports_process_start_failure(self) -> None:
        with mock.patch.object(
            MODULE.subprocess, "run", side_effect=FileNotFoundError("aws")
        ):
            with self.assertRaisesRegex(MODULE.EnrollmentError, "could not start"):
                MODULE.put_parameter(
                    "us-east-2", "/reviewed/name", "lv_live_secret-token"
                )

    def test_put_parameter_reports_timeout(self) -> None:
        with mock.patch.object(
            MODULE.subprocess,
            "run",
            side_effect=MODULE.subprocess.TimeoutExpired("aws", 30),
        ):
            with self.assertRaisesRegex(
                MODULE.EnrollmentParameterOutcomeUnknown,
                "timed out.*may have completed",
            ):
                MODULE.put_parameter(
                    "us-east-2", "/reviewed/name", "lv_live_secret-token"
                )

    def test_put_parameter_retries_one_safe_service_rejection(self) -> None:
        throttled = mock.Mock(
            returncode=255,
            stderr="An error occurred (ThrottlingException) while writing lv_live_secret-token",
        )
        completed = mock.Mock(returncode=0, stderr="")
        with (
            mock.patch.object(
                MODULE.subprocess, "run", side_effect=[throttled, completed]
            ) as run,
            mock.patch.object(MODULE.time, "sleep") as sleep,
        ):
            MODULE.put_parameter("us-east-2", "/reviewed/name", "lv_live_secret-token")
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(MODULE.RETRY_SECONDS)

    def test_put_parameter_stops_after_one_safe_service_retry(self) -> None:
        throttled = mock.Mock(
            returncode=255,
            stderr="An error occurred (ThrottlingException) while writing lv_live_secret-token",
        )
        with (
            mock.patch.object(
                MODULE.subprocess, "run", side_effect=[throttled, throttled]
            ) as run,
            mock.patch.object(MODULE.time, "sleep") as sleep,
            self.assertRaisesRegex(
                MODULE.EnrollmentError, "ThrottlingException.*exit status 255"
            ) as raised,
        ):
            MODULE.put_parameter("us-east-2", "/reviewed/name", "lv_live_secret-token")
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(MODULE.RETRY_SECONDS)
        self.assertNotIn("lv_live_secret-token", str(raised.exception))

    def test_put_parameter_preserves_unknown_server_error_outcome(self) -> None:
        failed = mock.Mock(
            returncode=255,
            stderr="An error occurred (InternalServerError) while writing lv_live_secret-token",
        )
        with (
            mock.patch.object(MODULE.subprocess, "run", side_effect=[failed, failed]),
            mock.patch.object(MODULE.time, "sleep") as sleep,
            self.assertRaisesRegex(
                MODULE.EnrollmentParameterOutcomeUnknown,
                "InternalServerError.*may have completed",
            ) as raised,
        ):
            MODULE.put_parameter("us-east-2", "/reviewed/name", "lv_live_secret-token")
        sleep.assert_called_once_with(MODULE.RETRY_SECONDS)
        self.assertNotIn("lv_live_secret-token", str(raised.exception))

    def test_put_parameter_does_not_retry_unknown_timeout(self) -> None:
        with (
            mock.patch.object(
                MODULE.subprocess,
                "run",
                side_effect=MODULE.subprocess.TimeoutExpired("aws", 30),
            ) as run,
            mock.patch.object(MODULE.time, "sleep") as sleep,
            self.assertRaises(MODULE.EnrollmentParameterOutcomeUnknown),
        ):
            MODULE.put_parameter("us-east-2", "/reviewed/name", "lv_live_secret-token")
        run.assert_called_once()
        sleep.assert_not_called()

    def test_put_parameter_reports_only_safe_rejected_aws_error_code(self) -> None:
        for error_code in (
            "AccessDeniedException",
            "ExpiredToken",
            "ExpiredTokenException",
            "IncompleteSignature",
            "IncompleteSignatureException",
            "InvalidClientTokenId",
            "InvalidSignatureException",
            "RequestExpired",
            "SignatureDoesNotMatch",
            "UnrecognizedClientException",
        ):
            with self.subTest(error_code=error_code):
                completed = mock.Mock(
                    returncode=255,
                    stderr=f"An error occurred ({error_code}) while writing lv_live_secret-token",
                )
                with mock.patch.object(
                    MODULE.subprocess, "run", return_value=completed
                ):
                    with self.assertRaisesRegex(
                        MODULE.EnrollmentError, error_code
                    ) as raised:
                        MODULE.put_parameter(
                            "us-east-2", "/reviewed/name", "lv_live_secret-token"
                        )
                self.assertNotIsInstance(
                    raised.exception, MODULE.EnrollmentParameterOutcomeUnknown
                )
                self.assertNotIn("lv_live_secret-token", str(raised.exception))

    def test_put_parameter_classifies_safe_local_aws_failure(self) -> None:
        for stderr, expected_class in (
            (
                "Unable to locate credentials for lv_live_secret-token",
                "MissingCredentials",
            ),
            (
                "SSL validation failed for https://private.example.com with lv_live_secret-token",
                "TLSValidation",
            ),
        ):
            with self.subTest(expected_class=expected_class):
                completed = mock.Mock(returncode=255, stderr=stderr)
                with mock.patch.object(
                    MODULE.subprocess, "run", return_value=completed
                ):
                    with self.assertRaisesRegex(
                        MODULE.EnrollmentError, expected_class
                    ) as raised:
                        MODULE.put_parameter(
                            "us-east-2", "/reviewed/name", "lv_live_secret-token"
                        )
                rendered = str(raised.exception)
                self.assertNotIn("lv_live_secret-token", rendered)
                self.assertNotIn("private.example.com", rendered)

    def test_put_parameter_preserves_unclassified_aws_outcome(self) -> None:
        for stderr in (
            "An error occurred (500) when calling the PutParameter operation",
            "Connection was closed before we received a valid response from endpoint URL: private.example.com with lv_live_secret-token",
            "unknown failure at private.example.com with lv_live_secret-token",
        ):
            with self.subTest(stderr=stderr):
                completed = mock.Mock(returncode=255, stderr=stderr)
                with mock.patch.object(
                    MODULE.subprocess, "run", return_value=completed
                ):
                    with self.assertRaisesRegex(
                        MODULE.EnrollmentParameterOutcomeUnknown,
                        "unclassified failure.*may have completed",
                    ) as raised:
                        MODULE.put_parameter(
                            "us-east-2", "/reviewed/name", "lv_live_secret-token"
                        )
                rendered = str(raised.exception)
                self.assertNotIn("lv_live_secret-token", rendered)
                self.assertNotIn("private.example.com", rendered)

    def test_fixed_replicas_share_route_slug_but_not_token_or_parameter(self) -> None:
        resource = [
            {
                "slug": "fileviewer-sandbox",
                "type": "tunnel",
                "status": "active",
                "resource_id": "MFkw-resource",
            }
        ]
        sharing = {"desired_state": "on", "serving_epoch": 7}
        credential = {
            "kind": "enrollment_token",
            "target": "agent",
            "claims": [{"type": "connector", "id": "fileviewer-sandbox"}],
            "api_key": "lv_live_replica-token",
            "expires_at": VALID_EXPIRY,
        }
        for replica in ("a", "b", "c"):
            target = f"fileviewer-nhp-replica-{replica}"
            with (
                self.subTest(target=target),
                mock.patch.object(
                    MODULE, "api_request", side_effect=[resource, sharing, credential]
                ) as request,
                mock.patch.object(MODULE, "put_parameter") as put,
            ):
                MODULE.prepare_enrollment(
                    "https://api.example.com",
                    "lv_live_account-key",
                    target,
                    "attempt-9",
                    "us-east-2",
                    now=FIXED_NOW,
                )
                self.assertEqual(
                    request.call_args_list[0].args[2],
                    "/v1/resources?slug=fileviewer-sandbox",
                )
                self.assertEqual(
                    request.call_args_list[2].kwargs["idempotency_key"],
                    f"headless-v2-attempt-9-{target}",
                )
                put.assert_called_once_with(
                    "us-east-2",
                    "/qurl-s3-connector/"
                    + f"fileviewer-nhp/replica-{replica}/bootstrap",
                    "lv_live_replica-token",
                )

    def test_uploader_target_has_exact_slug_and_parameter(self) -> None:
        target = "uploader-nhp-replica-c"
        responses = [
            [
                {
                    "slug": "uploader-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "on", "serving_epoch": 2},
            {
                "kind": "enrollment_token",
                "target": "agent",
                "claims": [{"type": "connector", "id": "uploader-sandbox"}],
                "api_key": "lv_live_uploader-token",
                "expires_at": VALID_EXPIRY,
            },
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
        ):
            MODULE.prepare_enrollment(
                "https://api.example.com",
                "lv_live_account-key",
                target,
                "attempt-5",
                "us-east-2",
                now=FIXED_NOW,
            )
        self.assertEqual(
            request.call_args_list[0].args[2], "/v1/resources?slug=uploader-sandbox"
        )
        self.assertEqual(
            request.call_args_list[2].kwargs["idempotency_key"],
            "headless-v2-attempt-5-uploader-nhp-replica-c",
        )
        put.assert_called_once_with(
            "us-east-2",
            "/qurl-s3-connector/uploader-nhp/replica-c/bootstrap",
            "lv_live_uploader-token",
        )

    def test_detect_fixed_target_has_shared_slug_and_distinct_parameter(self) -> None:
        target = "detect-nhp-replica-b"
        responses = [
            [
                {
                    "slug": "detect-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "on", "serving_epoch": 5},
            {
                "kind": "enrollment_token",
                "target": "agent",
                "claims": [{"type": "connector", "id": "detect-sandbox"}],
                "api_key": "lv_live_detect-token",
                "expires_at": VALID_EXPIRY,
            },
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
        ):
            MODULE.prepare_enrollment(
                "https://api.example.com",
                "lv_live_account-key",
                target,
                "attempt-6",
                "us-east-2",
                now=FIXED_NOW,
            )
        self.assertEqual(
            request.call_args_list[0].args[2], "/v1/resources?slug=detect-sandbox"
        )
        self.assertEqual(
            request.call_args_list[2].kwargs["idempotency_key"],
            "headless-v2-attempt-6-detect-nhp-replica-b",
        )
        put.assert_called_once_with(
            "us-east-2",
            "/qurl-s3-connector/detect-nhp/replica-b/bootstrap",
            "lv_live_detect-token",
        )

    def test_watermark_target_has_exact_slug_and_parameter(self) -> None:
        target = "watermark-nhp-replica-b"
        responses = [
            [
                {
                    "slug": "watermark-sandbox",
                    "type": "tunnel",
                    "status": "active",
                    "resource_id": "MFkw-resource",
                }
            ],
            {"desired_state": "on", "serving_epoch": 2},
            {
                "kind": "enrollment_token",
                "target": "agent",
                "claims": [{"type": "connector", "id": "watermark-sandbox"}],
                "api_key": "lv_live_watermark-token",
                "expires_at": VALID_EXPIRY,
            },
        ]
        with (
            mock.patch.object(MODULE, "api_request", side_effect=responses) as request,
            mock.patch.object(MODULE, "put_parameter") as put,
        ):
            MODULE.prepare_enrollment(
                "https://api.example.com",
                "lv_live_account-key",
                target,
                "attempt-4",
                "us-east-2",
                now=FIXED_NOW,
            )
        self.assertEqual(
            request.call_args_list[0].args[2], "/v1/resources?slug=watermark-sandbox"
        )
        self.assertEqual(
            request.call_args_list[2].kwargs["idempotency_key"],
            "headless-v2-attempt-4-watermark-nhp-replica-b",
        )
        put.assert_called_once_with(
            "us-east-2",
            "/qurl-watermark-service/nhp/replica-b/bootstrap",
            "lv_live_watermark-token",
        )


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner().run(suite)
    if result.testsRun == 0:
        print("error: no sandbox enrollment recovery tests ran", file=sys.stderr)
        raise SystemExit(1)
    raise SystemExit(0 if result.wasSuccessful() else 1)
