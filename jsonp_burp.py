# -*- coding: utf-8 -*-
"""JSONP Scanner: legacy Burp Extender API, Jython 2.7."""
from burp import IBurpExtender, IScannerCheck, IScanIssue
from java.net import URL
from java.util import UUID
from threading import Lock
import json
import re
import sys
try:
    from urlparse import urlsplit, urlunsplit
    from urllib import quote, unquote_plus
except ImportError:  # CPython test harness
    from urllib.parse import urlsplit, urlunsplit, quote, unquote_plus

# Edit these constants before loading the extension.
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_TRACKED_URLS = 10000
REQUIRE_SCOPE = True
MARKER_HEADER = 'X-JSONP-Scanner'
CALLBACK_PARAMS = ('callback', 'jsonp')


def candidates(url, callback):
    """Generate four variants, preserving other query parameters and their encoding."""
    parts = urlsplit(url)
    path = parts.path or '/'
    stripped = path.rstrip('/') or '/'
    last = stripped.rsplit('/', 1)[-1]
    if '.' in last:
        jsonp_path = stripped.rsplit('.', 1)[0] + '.jsonp'
    else:
        jsonp_path = (stripped if stripped != '/' else '') + '.jsonp'
    if path.endswith('/'):
        jsonp_path += '/'
    # Remove existing callback parameters, including percent-encoded names.
    query = [p for p in parts.query.split('&') if p and
             unquote_plus(p.split('=', 1)[0]).lower() not in CALLBACK_PARAMS]
    variants = [(jsonp_path, 'callback'), (jsonp_path, None),
                (path, 'callback'), (path, 'jsonp')]
    seen = set()
    for candidate_path, param in variants:
        q = list(query)
        if param:
            q.append(param + '=' + quote(callback, safe=''))
        target = urlunsplit((parts.scheme, parts.netloc, candidate_path, '&'.join(q), ''))
        if target not in seen:
            seen.add(target)
            yield target


def is_json(body):
    try:
        json.loads(body.strip())
        return True
    except (ValueError, TypeError):
        return False


def is_jsonp(body, callback):
    # Strictly accept a JSON argument, not arbitrary JavaScript.
    pattern = r'^\s*' + re.escape(callback) + r'\s*\(\s*(.*?)\s*\)\s*;?\s*$'
    match = re.match(pattern, body, re.DOTALL)
    return bool(match and is_json(match.group(1)))


def body_text(helpers, response, info):
    if len(response) > MAX_RESPONSE_BYTES:
        return None
    return helpers.bytesToString(response[info.getBodyOffset():])


class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._seen = set()
        self._lock = Lock()
        callbacks.setExtensionName('JSONP Scanner')
        callbacks.registerScannerCheck(self)
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()
        print('JSONP Scanner loaded. Scanner checks send additional GET requests; in-scope targets only by default.')

    def doPassiveScan(self, base):
        try:
            return self._scan(base)
        except Exception as exc:
            print('JSONP Scanner error: %s' % exc)
            return None

    def _scan(self, base):
        response = base.getResponse()
        if response is None:
            return None
        request_info = self._helpers.analyzeRequest(base)
        if str(request_info.getMethod()).upper() != 'GET':
            return None
        headers = list(request_info.getHeaders())
        if any(str(h).lower().startswith(MARKER_HEADER.lower() + ':') for h in headers[1:]):
            return None
        url = request_info.getUrl()
        if REQUIRE_SCOPE and not self._callbacks.isInScope(url):
            return None
        info = self._helpers.analyzeResponse(response)
        body = body_text(self._helpers, response, info)
        if body is None or not (str(info.getStatedMimeType()).lower() == 'json' or is_json(body)):
            return None
        key = str(url)
        with self._lock:
            if key in self._seen or len(self._seen) >= MAX_TRACKED_URLS:
                return None
            self._seen.add(key)
        callback = 'jsonp_test_' + str(UUID.randomUUID()).replace('-', '')
        service = base.getHttpService()
        for candidate in candidates(key, callback):
            target = urlsplit(candidate)
            path = target.path or '/'
            if target.query:
                path += '?' + target.query
            cleaned = [str(h) for h in headers[1:] if str(h).split(':', 1)[0].strip().lower()
                       not in ('content-length', 'content-type', 'transfer-encoding', 'accept-encoding', MARKER_HEADER.lower())]
            request_headers = ['GET ' + path + ' HTTP/1.1'] + cleaned
            request_headers.append('Accept-Encoding: identity')
            request_headers.append(MARKER_HEADER + ': 1')
            request = self._helpers.buildHttpMessage(request_headers, None)
            print('JSONP Scanner testing: ' + candidate)
            result = self._callbacks.makeHttpRequest(service, request)
            if result is None or result.getResponse() is None:
                continue
            result_response = result.getResponse()
            result_info = self._helpers.analyzeResponse(result_response)
            if not 200 <= result_info.getStatusCode() < 300:
                continue
            result_body = body_text(self._helpers, result_response, result_info)
            if result_body is not None and is_jsonp(result_body, callback):
                return [CustomScanIssue(service, URL(candidate), [base, result], callback)]
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        return None

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return -1 if (existingIssue.getIssueName() == newIssue.getIssueName() and
                      str(existingIssue.getUrl()) == str(newIssue.getUrl())) else 0


class CustomScanIssue(IScanIssue):
    def __init__(self, service, url, messages, callback):
        self._service, self._url, self._messages, self._callback = service, url, messages, callback
    def getUrl(self): return self._url
    def getIssueName(self): return 'JSONP callback supported'
    def getIssueType(self): return 0
    def getSeverity(self): return 'Information'
    def getConfidence(self): return 'Firm'
    def getIssueBackground(self):
        return ('JSONP executes data as JavaScript in the requesting page. It may expose sensitive '
                'authenticated data across origins depending on cookie policy and endpoint behavior.')
    def getRemediationBackground(self): return None
    def getIssueDetail(self):
        return ('The response invoked the supplied random callback <b>' + self._callback +
                '</b> with a JSON value. Review the attached request and response. '
                'This confirms JSONP behavior, not exposure of sensitive data or a vulnerability.')
    def getRemediationDetail(self):
        return 'Prefer JSON without JSONP for sensitive data and restrict cross-origin access appropriately.'
    def getHttpMessages(self): return self._messages
    def getHttpService(self): return self._service
