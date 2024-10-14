from burp import IBurpExtender, IHttpListener, IScannerCheck, ITab, IScanIssue
from javax.swing import JPanel, JLabel, JTextField, JButton, JList, DefaultListModel, JScrollPane, BoxLayout, JCheckBox
from java.awt import Dimension
from java.util import List, ArrayList

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        # Set extension name
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Unusual Header Detector")

        # Initialize UI elements
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))

        # Default ignored headers (ordered alphabetically)
        self.ignoredHeadersModel = DefaultListModel()
        self.defaultIgnoredHeaders = sorted([
            "Accept", "Accept-Encoding", "Accept-Language", "Accept-Ranges", "Access-Control-Allow-Origin",
            "Access-Control-Allow-Methods", "Access-Control-Allow-Headers", "Access-Control-Allow-Credentials",
            "Access-Control-Max-Age", "Access-Control-Request-Method", "Access-Control-Request-Headers",
            "Age", "Alt-Svc", "Authorization", "Cache-Control", "Cf-Cache-Status", "Cf-Ray", "Connection",
            "Content-Disposition", "Content-Encoding", "Content-Language", "Content-Length", "Content-MD5",
            "Content-Range", "Content-Security-Policy", "Content-Type", "Cookie", "Date", "ETag", "Expires",
            "Host", "If-Match", "If-Modified-Since", "If-None-Match", "If-Unmodified-Since", "Last-Modified",
            "Location", "Nel", "Origin", "Permissions-Policy", "Pragma", "Priority", "Range", "Referer", "Referrer", 
            "Referrer-Policy", "Report-To", "Sec-Fetch-Dest", "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-User",
            "Server", "Server-Timeing", "Set-Cookie", "Speculation-Rules", "Strict-Transport-Security", "Te",
            "Transfer-Encoding", "Upgrade-Insecure-Requests", "User-Agent", "Vary", "X-AspNet-Version", 
            "X-AspNetMvc-Version", "X-Cloud-Trace-Context", "X-Content-Type-Options", "X-DNS-Prefetch-Control", "X-Frame-Options",
            "X-Goog-ACL", "X-Goog-Allowed-Resources", "X-Goog-API-Version", "X-Goog-Bucket-Object-Lock-Enabled",
            "X-Goog-Bucket-Retention-Period", "X-Goog-Bypass-Governance-Retention", "X-Goog-Component-Count",
            "X-Goog-Content-Length-Range", "X-Goog-Content-SHA256", "X-Goog-Copy-Source", "X-Goog-Copy-Source-Generation",
            "X-Goog-Copy-Source-If-Generation-Match", "X-Goog-Copy-Source-If-Match", "X-Goog-Copy-Source-If-Metageneration-Match",
            "X-Goog-Copy-Source-If-Modified-Since", "X-Goog-Copy-Source-If-None-Match", "X-Goog-Copy-Source-If-Unmodified-Since",
            "X-Goog-Custom-Audit-KEY", "X-Goog-Custom-Time", "X-Goog-Date", "X-Goog-Encryption-Algorithm",
            "X-Goog-Encryption-Key", "X-Goog-Encryption-Key-SHA256", "X-Goog-Encryption-KMS-Key-Name",
            "X-Goog-Expiration", "X-Goog-Generation", "X-Goog-Hash", "X-Goog-IF-Generation-Match",
            "X-Goog-IF-Metageneration-Match", "X-Goog-Interop-List-Objects-Format", "X-Goog-Meta-KEY",
            "X-Goog-Metadata-Directive", "X-Goog-Metageneration", "X-Goog-Object-Lock-Mode",
            "X-Goog-Object-Lock-Retain-Until-Date", "X-Goog-Project-ID", "X-Goog-Resumable", "X-Goog-Storage-Class",
            "X-Goog-Stored-Content-Encoding", "X-Goog-Stored-Content-Length", "X-Goog-User-Project",
            "X-Guploader-Uploadid", "X-Powered-By", "X-Sourcemap", "X-XSS-Protection"
        ])


        for header in self.defaultIgnoredHeaders:
            self.ignoredHeadersModel.addElement(header)

        # Adjust GUI sizes: scrollable headers list, single line input box
        self.headerList = JList(self.ignoredHeadersModel)
        self.headerList.setVisibleRowCount(30)  # Show 30 lines in the list
        self.headerListScrollPane = JScrollPane(self.headerList)

        self.addHeaderField = JTextField('', 50)  # One line, 50 characters wide
        self.addButton = JButton("Add Header", actionPerformed=self.addHeader)
        self.removeButton = JButton("Remove Header", actionPerformed=self.removeHeader)

        # Checkbox for case sensitivity and in-scope restriction
        self.caseSensitiveCheckbox = JCheckBox("Case Sensitive")
        self.caseSensitiveCheckbox.setSelected(False)  # Default to case-insensitive

        self.scopeOnlyCheckbox = JCheckBox("Apply only to in-scope items")
        self.scopeOnlyCheckbox.setSelected(True)  # Default to only in-scope items

        # Add components to the panel
        self.panel.add(JLabel("Headers to ignore:"))
        self.panel.add(self.headerListScrollPane)  # Scrollable headers list
        self.panel.add(JLabel("Add new header:"))
        self.panel.add(self.addHeaderField)  # Single-line input
        self.panel.add(self.addButton)
        self.panel.add(self.removeButton)
        self.panel.add(self.caseSensitiveCheckbox)
        self.panel.add(self.scopeOnlyCheckbox)

        # Register HTTP listener
        self._callbacks.registerHttpListener(self)

        # Set the custom tab in the UI
        self._callbacks.addSuiteTab(self)

    def getTabCaption(self):
        return "Unusual Header Detector"

    def getUiComponent(self):
        return self.panel

    def addHeader(self, event):
        header = self.addHeaderField.getText().strip()
        if header and header not in [self.ignoredHeadersModel.getElementAt(i) for i in range(self.ignoredHeadersModel.size())]:
            self.ignoredHeadersModel.addElement(header)
            self.addHeaderField.setText("")

    def removeHeader(self, event):
        selectedHeader = self.headerList.getSelectedValue()
        if selectedHeader:
            self.ignoredHeadersModel.removeElement(selectedHeader)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # We don't want to assess any injected headers from Burp or other plugins, 
        # so if an Active Scan is the trigger of the request, just simply return without doing anything
        if toolFlag == IBurpExtenderCallbacks.TOOL_SCANNER:
            return
            
        # Check if we should apply this extension only to in-scope items
        if self.scopeOnlyCheckbox.isSelected() and not self._callbacks.isInScope(self._helpers.analyzeRequest(messageInfo).getUrl()):
            return  # Skip out-of-scope items

        # Get the headers from the request or response
        if messageIsRequest:
            analyzedMessage = self._helpers.analyzeRequest(messageInfo)
            location = "Request"
        else:
            analyzedMessage = self._helpers.analyzeResponse(messageInfo.getResponse())
            location = "Response"

        headers = analyzedMessage.getHeaders()

        # Determine case sensitivity
        caseSensitive = self.caseSensitiveCheckbox.isSelected()

        # Get the ignored headers
        ignoredHeaders = [self.ignoredHeadersModel.getElementAt(i) for i in range(self.ignoredHeadersModel.size())]

        # Process headers to identify unusual ones
        unusualHeaders = set()
        for header in headers:
            # Some rare situations have a colon in the HTTP Verb line, this next condition filters those out
            if " " in header:
                potentialHeader = header.split(" ")[0]
                # All headers and their values are split by a colon.  This ensures there is a colon and we get the first part
                if ":" in potentialHeader:
                    headerName = potentialHeader.split(":")[0].strip()
    
                    # Perform case-sensitive or case-insensitive matching
                    if caseSensitive:
                        if headerName not in ignoredHeaders:
                            print("Unusual header found: " + headerName)
                            unusualHeaders.add(headerName)
                    else:
                        if headerName.lower() not in [ignoredHeader.lower() for ignoredHeader in ignoredHeaders]:
                            print("Unusual header found: " + headerName.lower())
                            unusualHeaders.add(headerName)

        if unusualHeaders:
            # Formatting the issue text with markers and proper new lines (using Python 2 string formatting)
            headers = "<br />".join(["%s" % (header) for header in unusualHeaders])

            # Raise separate issues for request and response headers
            if location == "Request":
                issueText = "Unusual request headers detected:<br /><br />" + headers
            else:
                issueText = "Unusual response headers detected:<br /><br />" + headers

            self._callbacks.addScanIssue(
                CustomScanIssue(
                    messageInfo.getHttpService(), location, self._helpers.analyzeRequest(messageInfo).getUrl(), messageInfo, issueText
                )
            )

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, location, url, httpMessages, detail):
        self._httpService = httpService
        self._url = url
        self._location = location
        self._httpMessages = [httpMessages]
        self._detail = detail

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "Unusual HTTP " + self._location + " Header(s) Detected"

    def getIssueType(self):
        return 0x08000000  # Information issue

    def getSeverity(self):
        return "Information"

    def getConfidence(self):
        return "Certain"

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None
