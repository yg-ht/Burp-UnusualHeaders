"""Adapter tests using lightweight doubles for Burp and Swing APIs."""

from concurrent.futures import ThreadPoolExecutor
import sys
from threading import Lock
from types import ModuleType
import unittest


class _IBurpExtender(object):
    pass


class _IHttpListener(object):
    pass


class _IScannerCheck(object):
    pass


class _ITab(object):
    pass


class _IScanIssue(object):
    pass


class _Panel(object):
    def __init__(self):
        self.children = []

    def setLayout(self, layout):
        self.layout = layout

    def add(self, component):
        self.children.append(component)


class _Label(object):
    def __init__(self, text):
        self.text = text


class _TextField(object):
    def __init__(self, text, columns):
        self.text = text
        self.columns = columns

    def getText(self):
        return self.text

    def setText(self, text):
        self.text = text


class _Button(object):
    def __init__(self, text, actionPerformed=None):
        self.text = text
        self.actionPerformed = actionPerformed


class _DefaultListModel(object):
    def __init__(self):
        self.values = []

    def addElement(self, value):
        self.values.append(value)

    def removeElement(self, value):
        if value in self.values:
            self.values.remove(value)

    def getElementAt(self, index):
        return self.values[index]

    def size(self):
        return len(self.values)


class _List(object):
    def __init__(self, model):
        self.model = model
        self.selected = None

    def setVisibleRowCount(self, count):
        self.visible_rows = count

    def getSelectedValue(self):
        return self.selected


class _ScrollPane(object):
    def __init__(self, component):
        self.component = component


class _BoxLayout(object):
    Y_AXIS = 1

    def __init__(self, component, axis):
        self.component = component
        self.axis = axis


class _CheckBox(object):
    def __init__(self, text, itemStateChanged=None):
        self.text = text
        self.selected = False
        self.itemStateChanged = itemStateChanged

    def setSelected(self, selected):
        self.selected = selected

    def isSelected(self):
        return self.selected

class _ArrayList(list):
    def add(self, value):
        self.append(value)

    def size(self):
        return len(self)


def _install_api_doubles():
    """Install import-compatible modules before loading the extension."""
    burp = ModuleType("burp")
    burp.IBurpExtender = _IBurpExtender
    burp.IHttpListener = _IHttpListener
    burp.IScannerCheck = _IScannerCheck
    burp.ITab = _ITab
    burp.IScanIssue = _IScanIssue

    javax = ModuleType("javax")
    swing = ModuleType("javax.swing")
    swing.JPanel = _Panel
    swing.JLabel = _Label
    swing.JTextField = _TextField
    swing.JButton = _Button
    swing.JList = _List
    swing.DefaultListModel = _DefaultListModel
    swing.JScrollPane = _ScrollPane
    swing.BoxLayout = _BoxLayout
    swing.JCheckBox = _CheckBox

    java = ModuleType("java")
    awt = ModuleType("java.awt")
    awt.Dimension = object
    util = ModuleType("java.util")
    util.List = list
    util.ArrayList = _ArrayList

    sys.modules["burp"] = burp
    sys.modules["javax"] = javax
    sys.modules["javax.swing"] = swing
    sys.modules["java"] = java
    sys.modules["java.awt"] = awt
    sys.modules["java.util"] = util


_install_api_doubles()

from UnusualHeaders import BurpExtender  # noqa: E402


class _Url(object):
    def __init__(self, value):
        self.value = value

    def getPath(self):
        path_start = self.value.find("/", self.value.find("://") + 3)
        return self.value[path_start:] if path_start >= 0 else "/"

    def toString(self):
        return self.value


class _HttpService(object):
    def getProtocol(self):
        return "https"

    def getHost(self):
        return "example.test"

    def getPort(self):
        return 443


class _AnalysedMessage(object):
    def __init__(self, headers, url=None):
        self.headers = headers
        self.url = url

    def getHeaders(self):
        return self.headers

    def getUrl(self):
        return self.url


class _Message(object):
    def __init__(self, request_headers, response_headers=None, path="/path"):
        self.url = _Url("https://example.test%s" % path)
        self.request_info = _AnalysedMessage(request_headers, self.url)
        self.response_info = (
            _AnalysedMessage(response_headers)
            if response_headers is not None else None
        )
        self.service = _HttpService()

    def getResponse(self):
        return self.response_info

    def getHttpService(self):
        return self.service


class _Helpers(object):
    def analyzeRequest(self, message):
        return message.request_info

    def analyzeResponse(self, response):
        return response


class _Callbacks(object):
    TOOL_PROXY = 4
    TOOL_SCANNER = 16
    TOOL_INTRUDER = 32
    TOOL_REPEATER = 64

    def __init__(self, in_scope=True):
        self.helpers = _Helpers()
        self.in_scope = in_scope
        self.http_listeners = []
        self.scanner_checks = []
        self.tabs = []
        self.issues = []
        self.issue_lock = Lock()

    def getHelpers(self):
        return self.helpers

    def setExtensionName(self, name):
        self.extension_name = name

    def registerHttpListener(self, listener):
        self.http_listeners.append(listener)

    def registerScannerCheck(self, check):
        self.scanner_checks.append(check)

    def addSuiteTab(self, tab):
        self.tabs.append(tab)

    def isInScope(self, url):
        return self.in_scope

    def addScanIssue(self, issue):
        with self.issue_lock:
            self.issues.append(issue)


def _new_extension(in_scope=True):
    callbacks = _Callbacks(in_scope=in_scope)
    extension = BurpExtender()
    extension.registerExtenderCallbacks(callbacks)
    return extension, callbacks


def _request_headers(unusual_header="X-Unusual"):
    return [
        "GET /path HTTP/1.1",
        "Host: example.test",
        "%s: request-value" % unusual_header,
    ]


def _response_headers(unusual_header="X-Unusual"):
    return [
        "HTTP/1.1 200 OK",
        "Content-Type: text/plain",
        "%s: response-value" % unusual_header,
    ]


class RegistrationTests(unittest.TestCase):
    def test_registers_listener_passive_check_and_ui_tab(self):
        extension, callbacks = _new_extension()

        self.assertEqual([extension], callbacks.http_listeners)
        self.assertEqual([extension], callbacks.scanner_checks)
        self.assertEqual([extension], callbacks.tabs)


class ListenerTests(unittest.TestCase):
    def test_scanner_request_is_skipped(self):
        extension, callbacks = _new_extension()
        message = _Message(_request_headers())

        extension.processHttpMessage(callbacks.TOOL_SCANNER, True, message)

        self.assertEqual([], callbacks.issues)

    def test_scanner_response_is_processed(self):
        extension, callbacks = _new_extension()
        message = _Message(_request_headers(), _response_headers())

        extension.processHttpMessage(callbacks.TOOL_SCANNER, False, message)

        self.assertEqual(1, len(callbacks.issues))
        self.assertEqual("Response", callbacks.issues[0]._location)

    def test_out_of_scope_message_is_skipped_by_default(self):
        extension, callbacks = _new_extension(in_scope=False)
        message = _Message(_request_headers())

        extension.processHttpMessage(callbacks.TOOL_REPEATER, True, message)

        self.assertEqual([], callbacks.issues)

    def test_scope_checkbox_can_enable_out_of_scope_listener_processing(self):
        extension, callbacks = _new_extension(in_scope=False)
        message = _Message(_request_headers())
        extension.scopeOnlyCheckbox.setSelected(False)
        extension._scopeOnlyChanged(None)

        extension.processHttpMessage(callbacks.TOOL_REPEATER, True, message)

        self.assertEqual(1, len(callbacks.issues))

    def test_listener_supports_proxy_repeater_and_intruder(self):
        for tool_flag in (
                _Callbacks.TOOL_PROXY,
                _Callbacks.TOOL_REPEATER,
                _Callbacks.TOOL_INTRUDER):
            extension, callbacks = _new_extension()
            message = _Message(_request_headers())

            extension.processHttpMessage(tool_flag, True, message)

            self.assertEqual(1, len(callbacks.issues))

    def test_concurrent_duplicate_callbacks_raise_one_listener_issue(self):
        extension, callbacks = _new_extension()
        message = _Message(_request_headers())

        with ThreadPoolExecutor(max_workers=12) as executor:
            futures = [
                executor.submit(
                    extension.processHttpMessage,
                    callbacks.TOOL_REPEATER,
                    True,
                    message,
                )
                for unused_index in range(100)
            ]
            for future in futures:
                future.result()

        self.assertEqual(1, len(callbacks.issues))

    def test_listener_cache_is_bounded_and_evicts_oldest_identity(self):
        extension, unused_callbacks = _new_extension()
        extension.MAX_REPORTED_FINDINGS = 2

        self.assertTrue(extension._deduplifyFinding("first"))
        self.assertTrue(extension._deduplifyFinding("second"))
        self.assertTrue(extension._deduplifyFinding("third"))
        self.assertEqual(2, len(extension._reportedFindings))
        self.assertTrue(extension._deduplifyFinding("first"))


class PassiveScanTests(unittest.TestCase):
    def test_returns_request_and_response_issues_without_direct_submission(self):
        extension, callbacks = _new_extension(in_scope=False)
        message = _Message(_request_headers(), _response_headers())

        issues = extension.doPassiveScan(message)

        self.assertEqual(2, issues.size())
        self.assertEqual(set(["Request", "Response"]), set(
            issue._location for issue in issues
        ))
        self.assertEqual([], callbacks.issues)

    def test_missing_response_returns_only_request_issue(self):
        extension, unused_callbacks = _new_extension()
        message = _Message(_request_headers())

        issues = extension.doPassiveScan(message)

        self.assertEqual(1, issues.size())
        self.assertEqual("Request", issues[0]._location)

    def test_response_only_finding_returns_only_response_issue(self):
        extension, unused_callbacks = _new_extension()
        message = _Message(
            ["GET /path HTTP/1.1", "Host: example.test"],
            _response_headers(),
        )

        issues = extension.doPassiveScan(message)

        self.assertEqual(1, issues.size())
        self.assertEqual("Response", issues[0]._location)

    def test_no_findings_returns_none(self):
        extension, unused_callbacks = _new_extension()
        message = _Message(
            ["GET /path HTTP/1.1", "Host: example.test"],
            ["HTTP/1.1 200 OK", "Content-Type: text/plain"],
        )

        self.assertIsNone(extension.doPassiveScan(message))

    def test_active_scan_is_not_implemented(self):
        extension, unused_callbacks = _new_extension()

        self.assertIsNone(extension.doActiveScan(None, None))

    def test_issue_detail_escapes_untrusted_header_name(self):
        extension, unused_callbacks = _new_extension()
        message = _Message(_request_headers("<script>"))

        issue = extension.doPassiveScan(message)[0]

        self.assertIn("&lt;script&gt;", issue.getIssueDetail())
        self.assertNotIn("<script>", issue.getIssueDetail())


class ConsolidationTests(unittest.TestCase):
    class _Issue(object):
        def __init__(self, identity, origin):
            self._identity = identity
            self._origin = origin

    def test_prefers_new_passive_issue_over_existing_listener_issue(self):
        extension, unused_callbacks = _new_extension()
        existing = self._Issue(("same",), "listener")
        new = self._Issue(("same",), "passive")

        self.assertEqual(1, extension.consolidateDuplicateIssues(existing, new))

    def test_keeps_existing_exact_duplicate(self):
        extension, unused_callbacks = _new_extension()
        existing = self._Issue(("same",), "passive")
        new = self._Issue(("same",), "passive")

        self.assertEqual(-1, extension.consolidateDuplicateIssues(existing, new))

    def test_keeps_both_distinct_findings(self):
        extension, unused_callbacks = _new_extension()
        existing = self._Issue(("first",), "passive")
        new = self._Issue(("second",), "passive")

        self.assertEqual(0, extension.consolidateDuplicateIssues(existing, new))


class SettingsSnapshotTests(unittest.TestCase):
    def test_worker_snapshot_changes_only_after_ui_action(self):
        extension, unused_callbacks = _new_extension()
        extension.caseSensitiveCheckbox.setSelected(True)

        self.assertFalse(extension._getSettingsSnapshot()[1])

        extension._caseSensitivityChanged(None)

        self.assertTrue(extension._getSettingsSnapshot()[1])

    def test_added_header_is_published_in_complete_snapshot(self):
        extension, unused_callbacks = _new_extension()
        extension.addHeaderField.setText("X-Custom-Known")

        extension.addHeader(None)

        ignored_headers = extension._getSettingsSnapshot()[0]
        self.assertIn("X-Custom-Known", ignored_headers)
        self.assertEqual("", extension.addHeaderField.getText())

    def test_removed_header_is_removed_from_published_snapshot(self):
        extension, unused_callbacks = _new_extension()
        extension.addHeaderField.setText("X-Custom-Known")
        extension.addHeader(None)
        extension.headerList.selected = "X-Custom-Known"

        extension.removeHeader(None)

        self.assertNotIn(
            "X-Custom-Known", extension._getSettingsSnapshot()[0]
        )

    def test_concurrent_settings_reads_return_complete_snapshots(self):
        extension, unused_callbacks = _new_extension()
        first_snapshot = (("First",), False, True)
        second_snapshot = (("Second",), True, False)
        valid_snapshots = set([first_snapshot, second_snapshot])
        invalid_snapshots = []

        with extension._settingsLock:
            (
                extension._ignoredHeadersSnapshot,
                extension._caseSensitive,
                extension._scopeOnly,
            ) = first_snapshot

        def publish_snapshots():
            for index in range(2000):
                snapshot = (
                    first_snapshot if index % 2 == 0 else second_snapshot
                )
                with extension._settingsLock:
                    (
                        extension._ignoredHeadersSnapshot,
                        extension._caseSensitive,
                        extension._scopeOnly,
                    ) = snapshot

        def read_snapshots():
            for unused_index in range(2000):
                snapshot = extension._getSettingsSnapshot()
                if snapshot not in valid_snapshots:
                    invalid_snapshots.append(snapshot)

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(publish_snapshots)]
            futures.extend(executor.submit(read_snapshots) for unused in range(4))
            for future in futures:
                future.result()

        self.assertEqual([], invalid_snapshots)


if __name__ == "__main__":
    unittest.main()
