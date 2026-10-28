import importlib.util
import json
import os
import sys
import threading
import types
import unittest
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

burp = types.ModuleType('burp')
for name in ('IBurpExtender', 'IScannerCheck', 'IScanIssue'):
    setattr(burp, name, type(name, (), {}))
sys.modules['burp'] = burp
java = types.ModuleType('java'); net = types.ModuleType('java.net'); util = types.ModuleType('java.util')
net.URL = lambda x: x
util.UUID = type('UUID', (), {'randomUUID': staticmethod(uuid.uuid4)})
sys.modules.update({'java': java, 'java.net': net, 'java.util': util})
spec = importlib.util.spec_from_file_location('scanner', os.path.join(os.path.dirname(__file__), '..', 'jsonp_burp.py'))
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)

class LogicTests(unittest.TestCase):
    def test_candidates_preserve_query_and_replace_callback(self):
        variants = list(s.candidates('http://example.test/api/user?x=a%2Fb&callback=old&%6asonp=old', 'abc'))
        self.assertEqual(variants, ['http://example.test/api/user.jsonp?x=a%2Fb&callback=abc',
                                    'http://example.test/api/user.jsonp?x=a%2Fb',
                                    'http://example.test/api/user?x=a%2Fb&callback=abc',
                                    'http://example.test/api/user?x=a%2Fb&jsonp=abc'])
    def test_extension_slash_root(self):
        self.assertIn('/a.jsonp?callback=x', list(s.candidates('https://x/a.json', 'x'))[0])
        self.assertIn('/a.jsonp/?callback=x', list(s.candidates('https://x/a/', 'x'))[0])
        self.assertIn('/.jsonp/?callback=x', list(s.candidates('https://x/', 'x'))[0])
    def test_jsonp_validation(self):
        self.assertTrue(s.is_jsonp('  cb({"a":[1,2]});\n', 'cb'))
        for data in ('other({"a":1})', 'cb({a:1})', 'cb({"a":1});alert(1)', 'cb(notjson)', '/*x*/cb({})'):
            self.assertFalse(s.is_jsonp(data, 'cb'), data)
    def test_json(self):
        self.assertTrue(s.is_json('[1,2]'))
        self.assertFalse(s.is_json('<html>error</html>'))

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path); q = parse_qs(parsed.query)
        cb = q.get('callback', q.get('jsonp', [None]))[0]
        if parsed.path == '/api' and cb:
            body = (cb + '(' + json.dumps({'name': 'alice'}) + ');').encode()
            typ = 'application/javascript'
        else:
            body = b'{"name":"alice"}'; typ = 'application/json'
        self.send_response(200); self.send_header('Content-Type', typ); self.end_headers(); self.wfile.write(body)
    def log_message(self, *args): pass

class Info:
    def __init__(self, msg):
        self.msg = msg
    def getMethod(self): return self.msg.method
    def getHeaders(self): return self.msg.headers
    def getUrl(self): return self.msg.url
    def getBodyOffset(self): return self.msg.index(b'\r\n\r\n') + 4
    def getStatedMimeType(self): return 'JSON' if b'application/json' in self.msg.split(b'\r\n\r\n')[0] else 'script'
    def getStatusCode(self): return int(self.msg.split(b' ', 2)[1])

class Message:
    def __init__(self, url, response, method='GET', headers=None):
        self.url, self.response, self.method = url, response, method
        self.headers = headers or [method + ' /api HTTP/1.1', 'Host: localhost', 'Content-Length: 5', 'Cookie: session=test']
    def getResponse(self): return self.response
    def getHttpService(self): return None

class Helpers:
    def analyzeRequest(self, m): return Info(m)
    def analyzeResponse(self, r): return Info(r)
    def bytesToString(self, b): return b.decode('latin1')
    def buildHttpMessage(self, headers, body): return headers

class Callbacks:
    def __init__(self, root): self.root = root; self.sent = []; self.in_scope = True
    def isInScope(self, url): return self.in_scope
    def makeHttpRequest(self, service, headers):
        self.sent.append(headers)
        path = headers[0].split(' ')[1]
        req = Request(self.root + path, headers={h.split(':', 1)[0]:h.split(':', 1)[1].strip() for h in headers[1:] if ':' in h and not h.lower().startswith('host:')})
        with urlopen(req, timeout=3) as res:
            payload = ('HTTP/1.1 %d OK\r\nContent-Type: %s\r\n\r\n' % (res.status, res.headers['Content-Type'])).encode() + res.read()
        return Message(self.root + path, payload)

class IntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(('127.0.0.1', 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True); cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.thread.join(); cls.server.server_close()
    def setUp(self):
        self.root = 'http://127.0.0.1:%d' % self.server.server_port
        self.cb = Callbacks(self.root); self.ext = s.BurpExtender()
        self.ext._callbacks = self.cb; self.ext._helpers = Helpers(); self.ext._seen = set(); self.ext._lock = threading.Lock()
        self.base = Message(self.root + '/api?x=1', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"name":"alice"}')
    def test_real_http_detection_dedup_and_headers(self):
        issues = self.ext.doPassiveScan(self.base)
        self.assertEqual(len(issues), 1); self.assertEqual(issues[0].getConfidence(), 'Firm')
        self.assertEqual(len(self.cb.sent), 3)
        self.assertFalse(any(h.lower().startswith('content-length:') for h in self.cb.sent[0]))
        self.assertTrue(any(h == 'Cookie: session=test' for h in self.cb.sent[0]))
        self.assertIsNone(self.ext.doPassiveScan(self.base)); self.assertEqual(len(self.cb.sent), 3)
    def test_scope_method_and_marker_skip(self):
        self.cb.in_scope = False; self.assertIsNone(self.ext.doPassiveScan(self.base))
        self.cb.in_scope = True; self.base.method = 'POST'; self.assertIsNone(self.ext.doPassiveScan(self.base))
        self.base.method = 'GET'; self.base.headers.append('X-JSONP-Scanner: 1'); self.assertIsNone(self.ext.doPassiveScan(self.base))
        self.assertEqual(self.cb.sent, [])
    def test_no_finding_for_json_only(self):
        self.base.url = self.root + '/ordinary'
        self.assertIsNone(self.ext.doPassiveScan(self.base)); self.assertEqual(len(self.cb.sent), 4)

if __name__ == '__main__': unittest.main()
