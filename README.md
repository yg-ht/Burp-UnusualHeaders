# Burp-InterestingHeaders

This is a Burp Suite extension that attempts to identify any unusual HTTP headers on requests or responses.  Occasionally I come across web applications that have a custom header but these often go unnoticed because of the general background noise of other headers going on.  I have used other extentions in the past and they all appear to come with a host of other features or limited lists of recognised headers and so inevitably I end up ignoring any issues they raise.

It does this by raising an issue for any header that is not on its list of known headers.  I think I have caught most of them, but, if there are others you spot please raise an issue and give me some details.  This BApp also has a UI element so that you can add headers during an assessment.  For example, you may have an unusual header, but upon inspection it is a benign header that you aren't interested in - in which case you can prevent it from being flagged again.

This extention is designed to rarely ever trigger an alert and therefore should be investigated when it does.
