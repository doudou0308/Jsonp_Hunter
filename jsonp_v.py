# -*- coding: utf-8 -*-
"""
JSONP Scanner for Burp Suite (Jython 2.7, legacy Extender API)

What it does
  * Watches every JSON response seen by Burp (Proxy / Repeater / Scanner / Intruder)
    through IHttpListener.
  * In background workers it probes four JSONP-style variants of the same path:
        <path>.jsonp?callback=test
        <path>.jsonp
        <path>?callback=test
        <path>?jsonp=test
  * Shows candidate, status, MIME, verdict and evidence in a "JSONP" tab.
  * HIT  : response is JavaScript AND the callback name is really invoked (test( ... ))
           -> also raises a Burp issue "Possible JSONP endpoint".
    SOFT : response is JavaScript but no callback invocation was found.
    MISS : response is not JavaScript.
  * Double-click a row or use the button to send the candidate request to Repeater.
  * Filter by text, show hits only, export CSV, clear.

Notes
  * Only JSON responses are touched; static assets are ignored.
  * Duplicate (url + payload) pairs are skipped.
  * Auto-scan can be disabled; manual scan is available from the context menu.
"""

from burp import (IBurpExtender, IHttpListener, IScanIssue, ITab,
                  IContextMenuFactory)
from urlparse import urlparse

import os
import sys
import time
import Queue
import codecs
import threading
import traceback

from javax.swing import (JPanel, JLabel, JTextField, JButton, JCheckBox,
                         JTable, JScrollPane, JMenuItem, JFileChooser,
                         SwingUtilities, JOptionPane)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout
from java.awt.event import MouseAdapter
from java.util import Vector
from java.lang import Exception as JavaException

PAYLOADS = ('.jsonp?callback=test', '.jsonp', '?callback=test', '?jsonp=test')
CALLBACK = {'.jsonp?callback=test': 'test', '?callback=test': 'test'}
COLUMNS = ['Time', 'Host', 'Original', 'Candidate', 'Payload',
           'Code', 'MIME', 'Verdict', 'Evidence']
WORKERS = 2


class _Model(DefaultTableModel):
    def isCellEditable(self, row, col):
        return False


class _Tab(ITab):
    def __init__(self, panel):
        self._panel = panel

    def getTabCaption(self):
        return 'JSONP'

    def getUiComponent(self):
        return self._panel


class _DblClick(MouseAdapter):
    def __init__(self, ext):
        self._ext = ext

    def mouseClicked(self, e):
        if e.getClickCount() == 2 and SwingUtilities.isLeftMouseButton(e):
            row = self._ext._table.rowAtPoint(e.getPoint())
            if row >= 0:
                self._ext.send_selected_to_repeater(row)


class CustomScanIssue(IScanIssue):
    def __init__(self, service, url, messages, candidate, payload,
                 code, mime, evidence):
        self._service = service
        self._url = url
        self._messages = messages
        self._candidate = candidate
        self._payload = payload
        self._code = code
        self._mime = mime
        self._evidence = evidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return 'Possible JSONP endpoint'

    def getIssueType(self):
        return 0x08000000

    def getSeverity(self):
        return 'Information'

    def getConfidence(self):
        return 'Firm'

    def getIssueBackground(self):
        return ('The response looks like JSONP: a JavaScript payload that '
                'invokes a caller-supplied callback function. If the endpoint '
                'returns sensitive data and reflects an arbitrary callback name, '
                'it may be readable cross-origin by any site that can load the '
                'script. This check only detects the pattern; it does not prove '
                'exploitability.')

    def getRemediationBackground(self):
        return ('Prefer JSON with CORS instead of JSONP. If JSONP is required, '
                'validate the callback name strictly, require authentication, '
                'and never expose sensitive data through it.')

    def getIssueDetail(self):
        return (u'Candidate request: %s\n'
                'Payload: %s\n'
                'HTTP status: %s\n'
                'Stated MIME: %s\n'
                'Evidence: %s\n\n'
                'Manually verify the callback reflection, authentication and '
                'cross-origin readability before reporting.' % (
                    self._candidate, self._payload, self._code,
                    self._mime, self._evidence))

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._messages

    def getHttpService(self):
        return self._service


class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory):

    # ---------------------------------------------------------------- setup
    def registerExtenderCallbacks(self, callbacks):
        SwingUtilities.invokeLater(lambda: self._register_on_edt(callbacks))

    def _register_on_edt(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('JSONP Scanner')

        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        self._enabled = True
        self._rows = []
        self._visible = []
        self._seen = set()
        self._lock = threading.Lock()
        self._queue = Queue.Queue()

        self._model = _Model(Vector(COLUMNS), 0)
        self._table = JTable(self._model)
        self._table.addMouseListener(_DblClick(self))

        self._filter = JTextField(18)
        self._filter.addActionListener(lambda e: self.refresh_table())

        self._only_hits = JCheckBox('Only HIT')
        self._only_hits.addItemListener(self._on_toggle)

        self._auto = JCheckBox('Auto scan', True)
        self._auto.addItemListener(self._on_auto)

        btn_filter = JButton('Filter')
        btn_filter.addActionListener(lambda e: self.refresh_table())

        btn_clear = JButton('Clear')
        btn_clear.addActionListener(lambda e: self.clear_rows())

        btn_export = JButton('Export CSV')
        btn_export.addActionListener(lambda e: self.export_csv())

        btn_repeater = JButton('Send to Repeater')
        btn_repeater.addActionListener(lambda e: self.send_selected_to_repeater())

        self._status = JLabel('Total: 0   HIT: 0')
        self._repeater_status = JLabel('Repeater: select a result row, then send')
        self._repeater_sequence = 0

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        top.add(JLabel('Filter:'))
        top.add(self._filter)
        top.add(btn_filter)
        top.add(self._only_hits)
        top.add(self._auto)
        top.add(btn_clear)
        top.add(btn_export)
        top.add(btn_repeater)

        panel = JPanel(BorderLayout())
        panel.add(top, BorderLayout.NORTH)
        panel.add(JScrollPane(self._table), BorderLayout.CENTER)
        footer = JPanel(BorderLayout())
        footer.add(self._status, BorderLayout.NORTH)
        footer.add(self._repeater_status, BorderLayout.SOUTH)
        panel.add(footer, BorderLayout.SOUTH)

        callbacks.addSuiteTab(_Tab(panel))
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        for _ in range(WORKERS):
            t = threading.Thread(target=self._worker)
            t.setDaemon(True)
            t.start()

        print('JSONP Scanner loaded. Results appear in the JSONP tab.')

    # ------------------------------------------------------------- UI events
    def _on_toggle(self, e):
        self.refresh_table()

    def _on_auto(self, e):
        self._enabled = (e.getStateChange() == 1)

    # ---------------------------------------------------------- HTTP traffic
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest or not self._enabled:
            return
        try:
            response = messageInfo.getResponse()
            if response is None:
                return
            request = messageInfo.getRequest()
            try:
                for h in self._helpers.analyzeRequest(request).getHeaders():
                    if h.lower().startswith('x-jsonp-probe:'):
                        return
            except:
                pass
            info = self._helpers.analyzeResponse(response)
            if info.getStatedMimeType() != 'JSON':
                return
            service = messageInfo.getHttpService()
            request = messageInfo.getRequest()
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            self._queue.put((service, request, url))
        except:
            traceback.print_exc(file=sys.stderr)

    # ------------------------------------------------------- context menu
    def createContextMenu(self, invocation):
        try:
            msgs = invocation.getSelectedMessages()
        except:
            msgs = None
        if not msgs:
            return None
        item = JMenuItem('JSONP: scan selected')

        def handler(e):
            for m in msgs:
                self._manual_scan(m)

        item.addActionListener(handler)
        return [item]

    def _manual_scan(self, messageInfo):
        try:
            response = messageInfo.getResponse()
            if response is None:
                print('JSONP: selected item has no response')
                return
            info = self._helpers.analyzeResponse(response)
            if info.getStatedMimeType() != 'JSON':
                print('JSONP: selected response is not JSON, skipped')
                return
            url = self._helpers.analyzeRequest(messageInfo).getUrl()
            self._queue.put((messageInfo.getHttpService(),
                             messageInfo.getRequest(), url))
            print('JSONP: queued ' + str(url))
        except:
            traceback.print_exc(file=sys.stderr)

    # ------------------------------------------------------------- workers
    def _worker(self):
        while True:
            service, request, url = self._queue.get()
            try:
                self._scan(service, request, url)
            except:
                traceback.print_exc(file=sys.stderr)
            finally:
                self._queue.task_done()

    def _scan(self, service, request, url):
        try:
            headers = self._helpers.analyzeRequest(request).getHeaders()
        except:
            return

        original = str(url)
        path_key = str(url.getHost()) + '|' + str(url.getPath())
        for payload in PAYLOADS:
            key = path_key + '|' + payload
            self._lock.acquire()
            try:
                if key in self._seen:
                    continue
                self._seen.add(key)
            finally:
                self._lock.release()

            candidate = self._construct_url(original, payload)
            if candidate is None:
                continue

            parts = urlparse(candidate)
            path = parts.path or '/'
            if parts.query:
                path = path + '?' + parts.query

            new_headers = ['GET ' + path + ' HTTP/1.1',
                           'Host: ' + parts.netloc,
                           'X-JSONP-Probe: 1']
            for h in headers[1:]:
                low = h.lower()
                if (low.startswith('host:') or
                        low.startswith('content-length:') or
                        low.startswith('content-type:') or
                        low.startswith('connection:')):
                    continue
                new_headers.append(h)

            candidate_request = self._helpers.buildHttpMessage(new_headers, None)
            try:
                result = self._callbacks.makeHttpRequest(service, candidate_request)
            except:
                traceback.print_exc(file=sys.stderr)
                continue

            self._record(service, url, candidate_request, candidate,
                         payload, result)

    def _construct_url(self, url, payload):
        try:
            p = urlparse(url)
            path = p.path or '/'
            payload_parts = urlparse(payload)
            new_path = path

            if payload_parts.path:
                ext = os.path.splitext(path)[1]
                if ext:
                    new_path = path[:-len(ext)] + payload_parts.path + ext
                else:
                    new_path = path + payload_parts.path

            queries = []
            if payload_parts.query:
                queries.append(payload_parts.query)
            if p.query:
                queries.append(p.query)

            result = p.scheme + '://' + p.netloc + new_path
            if queries:
                result = result + '?' + '&'.join(queries)
            return result
        except:
            return None

    # -------------------------------------------------------------- verdict
    def _record(self, service, original_url, request, candidate, payload, result):
        code = 0
        mime = ''
        verdict = 'ERR'
        evidence = ''
        message = None

        if result is not None:
            response = result.getResponse()
            if response is not None:
                message = result
                info = self._helpers.analyzeResponse(response)
                code = info.getStatusCode()
                mime = info.getStatedMimeType()

                ctype = ''
                for h in info.getHeaders():
                    if h.lower().startswith('content-type:'):
                        ctype = h.lower()
                        break

                body = unicode(self._helpers.bytesToString(response))
                try:
                    body = body[info.getBodyOffset():]
                except:
                    pass

                is_js = (mime == 'script' or
                         'javascript' in ctype or
                         'ecmascript' in ctype)
                cb = CALLBACK.get(payload)
                squeezed = (body.replace(u' ', u'').replace(u'\t', u'')
                            .replace(u'\r', u'').replace(u'\n', u''))

                evidence = self._snippet(body)

                if is_js and cb and (cb + '(') in squeezed:
                    verdict = 'HIT'
                elif is_js:
                    verdict = 'SOFT'
                else:
                    verdict = 'MISS'

        host = str(original_url.getHost())
        cells = [time.strftime('%H:%M:%S'),
                 host,
                 original_url.getPath(),
                 candidate,
                 payload,
                 str(code),
                 mime,
                 verdict,
                 evidence]

        meta = {
            'cells': cells,
            'host': host,
            'url': str(original_url),
            'candidate': candidate,
            'payload': payload,
            'verdict': verdict,
            'service': service,
            'request': request,
        }
        self._add_row(cells, meta)

        if verdict == 'HIT' and message is not None:
            issue = CustomScanIssue(service, original_url, [message],
                                    candidate, payload, code, mime, evidence)
            self._callbacks.addScanIssue(issue)

    def _snippet(self, body):
        try:
            s = body[:300]
            s = s.replace(u'\r', u' ').replace(u'\n', u' ')
            return s
        except:
            return ''

    # ---------------------------------------------------------------- table
    def _match(self, meta):
        if self._only_hits.isSelected() and meta['verdict'] != 'HIT':
            return False
        f = unicode(self._filter.getText()).strip().lower()
        if not f:
            return True
        hay = u' '.join([unicode(meta['host']), unicode(meta['url']),
                         unicode(meta['candidate']), unicode(meta['payload']),
                         unicode(meta['verdict'])]).lower()
        return f in hay

    def _add_row(self, cells, meta):
        def run():
            self._rows.append(meta)
            if self._match(meta):
                self._visible.append(meta)
                self._model.addRow(Vector(cells))
            self._update_status()
        SwingUtilities.invokeLater(run)

    def refresh_table(self):
        def run():
            self._model.setRowCount(0)
            self._visible = []
            for meta in self._rows:
                if self._match(meta):
                    self._visible.append(meta)
                    self._model.addRow(Vector(meta['cells']))
            self._update_status()
        SwingUtilities.invokeLater(run)

    def clear_rows(self):
        def run():
            self._rows = []
            self._visible = []
            self._model.setRowCount(0)
            self._update_status()
        SwingUtilities.invokeLater(run)

    def _update_status(self):
        hits = 0
        for m in self._rows:
            if m['verdict'] == 'HIT':
                hits += 1
        self._status.setText('Total: %d   HIT: %d' % (len(self._rows), hits))

    # ------------------------------------------------------------ repeater
    def _repeater_notice(self, text, error=False):
        def run():
            self._repeater_status.setText(text)
            if error:
                JOptionPane.showMessageDialog(
                    self._table, text, 'JSONP - Repeater',
                    JOptionPane.WARNING_MESSAGE)
        SwingUtilities.invokeLater(run)

    def send_selected_to_repeater(self, view_row=None):
        # Capture row metadata on EDT before another filter/clear can run.
        if not SwingUtilities.isEventDispatchThread():
            SwingUtilities.invokeLater(
                lambda: self.send_selected_to_repeater(view_row))
            return

        try:
            idx = (self._table.getSelectedRow()
                   if view_row is None else int(view_row))
            if idx < 0 or idx >= self._table.getRowCount():
                self._repeater_notice(
                    'Select a result row before sending to Repeater.', True)
                return

            model_row = self._table.convertRowIndexToModel(idx)
            if model_row < 0 or model_row >= len(self._visible):
                raise ValueError('Selected result is no longer available')

            meta = dict(self._visible[model_row])
            service = meta.get('service')
            request = meta.get('request')
            if service is None:
                raise ValueError('Selected result has no HTTP service')
            if request is None or len(request) == 0:
                raise ValueError('Selected result has no request bytes')

            host = unicode(service.getHost())
            port = int(service.getPort())
            protocol = unicode(service.getProtocol()).lower()
            if not host or not 1 <= port <= 65535:
                raise ValueError('Invalid destination host or port')
            if protocol not in (u'http', u'https'):
                raise ValueError('Unsupported destination protocol')

            self._repeater_sequence += 1
            caption = 'JSONP-%d' % self._repeater_sequence

            def send():
                try:
                    self._callbacks.sendToRepeater(
                        host, port, protocol == u'https', request, caption)
                    text = (u'Repeater API accepted %s. Open Repeater and '
                            u'look for tab %s; click Send there to issue it.'
                            % (caption, caption))
                    self._repeater_notice(text)
                    self._callbacks.printOutput(text)
                except (Exception, JavaException):
                    self._callbacks.printError(traceback.format_exc())
                    self._repeater_notice(
                        'Send to Repeater failed. See extension Errors.', True)

            SwingUtilities.invokeLater(send)
        except (Exception, JavaException):
            self._callbacks.printError(traceback.format_exc())
            self._repeater_notice(
                'Cannot send selected result. See extension Errors.', True)

    # ----------------------------------------------------------------- csv
    def export_csv(self):
        chooser = JFileChooser()
        if chooser.showSaveDialog(self._table) != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.lower().endswith('.csv'):
            path = path + '.csv'
        try:
            f = codecs.open(path, 'w', 'utf-8-sig')
            f.write(u','.join(COLUMNS) + u'\n')
            for m in self._rows:
                f.write(u','.join([self._csv(v) for v in m['cells']]) + u'\n')
            f.close()
            print('JSONP: exported ' + path)
        except:
            traceback.print_exc(file=sys.stderr)

    def _csv(self, value):
        try:
            s = u'%s' % (value,)
        except:
            s = u''
        if u',' in s or u'"' in s or u'\n' in s:
            s = u'"' + s.replace(u'"', u'""') + u'"'
        return s


# IScannerCheck is intentionally not registered: IHttpListener already covers
# Proxy / Repeater / Scanner traffic in real time, and issues are added directly.
