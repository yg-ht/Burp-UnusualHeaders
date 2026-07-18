# Burp-UnusualHeaders

Unusual Headers is a Burp Suite extension that identifies HTTP request and
response headers which are absent from its list of recognised headers. Custom
headers can otherwise disappear into the background noise of normal HTTP
traffic, including headers that appear only when an application encounters an
unusual or error condition.

The extension is designed to report rarely. A reported header should therefore
be reviewed to establish whether it exposes useful application or infrastructure
information.

## Requirements

The extension uses Burp's legacy Extender API and requires Jython 2.7. It retains
listener-based behaviour in both Burp Suite Community Edition and Professional,
while Professional users can also receive task-linked passive scan findings when
an audit task processes the traffic.

## Traffic coverage

The extension uses two complementary processing paths.

### HTTP listener

The listener provides immediate, zero-configuration coverage for traffic from
Proxy, Repeater, Intruder and other Burp tools. Scanner-generated requests are
excluded because their injected headers are likely to cause false positives;
Scanner responses remain covered because unusual server-generated headers may
still be useful.

Listener processing is restricted to URLs in the Burp suite scope by default.
Clear **Apply only to in-scope items** in the extension tab to inspect
out-of-scope traffic as well.

Listener findings are added directly to Burp. They may therefore have Task ID 0
and appear in **All issues** or on the site map rather than under a Dashboard
task.

### Passive scan check

The passive scan check analyses only the base request and response supplied by
Burp. It does not generate any additional traffic. Findings produced during an
audit are associated with that audit task and are visible with the task's
results on the Dashboard.

Scan tasks supply their base messages to the passive check. Burp's default live
audit also processes eligible Proxy traffic, subject to that task's configured
URL scope and scan configuration.

Burp Professional users can create a
[live audit task](https://portswigger.net/burp/documentation/desktop/running-scans/live-tasks/creating-live-tasks)
to apply passive checks to Proxy, Repeater or Intruder traffic. The listener
remains enabled so that Repeater and Intruder are still covered when no such task
has been configured.

## Duplicate findings

Findings are considered duplicates only when they have the same service, URL
path, request or response location, and case-normalised set of unusual header
names. Distinct header sets are retained. When Burp compares a direct listener
finding with the equivalent passive finding, the extension asks Burp to retain
the task-linked passive finding.

Direct listener findings also use a thread-safe, oldest-first cache to suppress
repeated reports for the same full URL and header set. The cache is limited to
10,000 entries to keep memory use bounded during long sessions.

## Configuration

The **Unusual Header Detector** tab lists the recognised headers. During an
assessment you can:

- Add a benign application-specific header to stop future reports for it.
- Remove a recognised header when you want it reported.
- Enable case-sensitive header-name matching.
- Include or exclude out-of-scope listener traffic.

Configuration changes affect subsequent listener and passive processing. They
are held in memory for the current extension session.

## Tests

The dependency-free tests exercise header detection, issue construction,
listener and passive coverage, duplicate consolidation, output escaping and
concurrent callback behaviour:

```console
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```
