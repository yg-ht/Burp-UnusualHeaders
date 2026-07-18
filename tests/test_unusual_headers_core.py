"""Regression tests for the dependency-free header detection logic."""

import unittest

from unusual_headers_core import build_finding_key, detect_unusual_headers


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


if __name__ == "__main__":
    unittest.main()
