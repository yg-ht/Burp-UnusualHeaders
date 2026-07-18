"""Pure header-detection helpers shared by the Burp integration paths.

This module deliberately avoids Burp and Swing imports.  Keeping the core logic
independent makes it possible to regression-test the extension under ordinary
Python while retaining compatibility with Jython 2.7.
"""


def detect_unusual_headers(headers, ignored_headers, case_sensitive):
    """Return the unusual header names found in Burp's analysed header lines.

    The parsing retains the extension's existing behaviour.  In particular, it
    examines the token before the first space so that a colon in an HTTP request
    target is not mistaken for a header delimiter.
    """
    if case_sensitive:
        comparable_ignored_headers = set(ignored_headers)
    else:
        comparable_ignored_headers = set(
            header.lower() for header in ignored_headers
        )

    unusual_headers = set()

    for header in headers:
        # Burp includes the request/status line in getHeaders().  Restricting the
        # delimiter check to the first token preserves the existing safeguard
        # against absolute-form request targets containing a colon.
        if " " not in header:
            continue

        potential_header = header.split(" ")[0]
        if ":" not in potential_header:
            continue

        header_name = potential_header.split(":")[0].strip()
        comparable_header_name = (
            header_name if case_sensitive else header_name.lower()
        )

        if comparable_header_name not in comparable_ignored_headers:
            unusual_headers.add(header_name)

    return unusual_headers


def build_finding_key(
        protocol,
        host,
        port,
        url,
        location,
        unusual_headers,
        case_sensitive):
    """Build the stable identity currently used for listener deduplication."""
    if case_sensitive:
        normalised_headers = sorted(unusual_headers)
    else:
        normalised_headers = sorted(
            header.lower() for header in unusual_headers
        )

    return "%s|%s|%s|%s|%s|%s" % (
        protocol,
        host,
        port,
        url,
        location,
        ",".join(normalised_headers)
    )
