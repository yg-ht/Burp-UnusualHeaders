"""Regression tests for the dependency-free header detection logic."""

import unittest

from unusual_headers_core import (
    build_finding_key,
    build_issue_identity,
    detect_unusual_headers,
    escape_html,
)


class DetectUnusualHeadersTests(unittest.TestCase):
    """Cover detection behaviour without requiring a running Burp instance."""

    def test_case_insensitive_detection_ignores_known_header_casing(self):
        headers = [
            "HTTP/1.1 200 OK",
            "content-type: text/plain",
            "X-Unusual: visible",
        ]

        result = detect_unusual_headers(headers, ["Content-Type"], False)

        self.assertEqual(set(["X-Unusual"]), result)

    def test_case_sensitive_detection_reports_different_header_casing(self):
        headers = ["content-type: text/plain"]

        result = detect_unusual_headers(headers, ["Content-Type"], True)

        self.assertEqual(set(["content-type"]), result)

    def test_duplicate_unusual_headers_are_reported_once(self):
        headers = ["X-Unusual: first", "X-Unusual: second"]

        result = detect_unusual_headers(headers, [], False)

        self.assertEqual(set(["X-Unusual"]), result)

    def test_absolute_form_request_line_is_not_reported_as_a_header(self):
        headers = ["GET http://example.test/path HTTP/1.1", "Host: example.test"]

        result = detect_unusual_headers(headers, ["Host"], False)

        self.assertEqual(set(), result)

    def test_header_without_space_retains_existing_ignored_behaviour(self):
        headers = ["X-Unusual:value"]

        result = detect_unusual_headers(headers, [], False)

        self.assertEqual(set(), result)

    def test_empty_header_collection_returns_no_findings(self):
        self.assertEqual(
            set(), detect_unusual_headers([], ["Content-Type"], False)
        )


class BuildFindingKeyTests(unittest.TestCase):
    """Cover stable identities used to avoid repeat listener findings."""

    def test_case_insensitive_key_normalises_order_and_casing(self):
        first = build_finding_key(
            "https", "example.test", 443, "https://example.test/path",
            "Response", set(["X-Zeta", "x-alpha"]), False
        )
        second = build_finding_key(
            "https", "example.test", 443, "https://example.test/path",
            "Response", set(["X-ALPHA", "x-zeta"]), False
        )

        self.assertEqual(first, second)

    def test_case_sensitive_key_preserves_header_casing(self):
        first = build_finding_key(
            "https", "example.test", 443, "https://example.test/path",
            "Request", set(["X-Unusual"]), True
        )
        second = build_finding_key(
            "https", "example.test", 443, "https://example.test/path",
            "Request", set(["x-unusual"]), True
        )

        self.assertNotEqual(first, second)


class BuildIssueIdentityTests(unittest.TestCase):
    """Cover the exact identity used by Burp issue consolidation."""

    def test_identity_normalises_header_order_and_casing(self):
        first = build_issue_identity(
            "https", "example.test", 443, "/path", "Response",
            set(["X-Zeta", "x-alpha"])
        )
        second = build_issue_identity(
            "https", "example.test", 443, "/path", "Response",
            set(["X-ALPHA", "x-zeta"])
        )

        self.assertEqual(first, second)

    def test_identity_keeps_different_locations_and_header_sets_distinct(self):
        request_identity = build_issue_identity(
            "https", "example.test", 443, "/path", "Request",
            set(["X-Unusual"])
        )
        response_identity = build_issue_identity(
            "https", "example.test", 443, "/path", "Response",
            set(["X-Unusual"])
        )
        different_headers = build_issue_identity(
            "https", "example.test", 443, "/path", "Request",
            set(["X-Different"])
        )
        different_path = build_issue_identity(
            "https", "example.test", 443, "/other", "Request",
            set(["X-Unusual"])
        )

        self.assertNotEqual(request_identity, response_identity)
        self.assertNotEqual(request_identity, different_headers)
        self.assertNotEqual(request_identity, different_path)


class EscapeHtmlTests(unittest.TestCase):
    """Ensure untrusted header names are safe in HTML issue details."""

    def test_escapes_html_metacharacters(self):
        self.assertEqual(
            "&lt;&amp;&gt;&quot;&#x27;",
            escape_html("<&>\"'")
        )


if __name__ == "__main__":
    unittest.main()
