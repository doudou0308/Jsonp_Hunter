"""Exercise actual GUI methods without importing Swing or starting workers."""
import ast
from pathlib import Path
import traceback
import unittest


class Swing:
    edt = True
    jobs = []

    @classmethod
    def isEventDispatchThread(cls):
        return cls.edt

    @classmethod
    def invokeLater(cls, fn):
        cls.jobs.append(fn)

    @classmethod
    def drain(cls):
        cls.edt = True
        while cls.jobs:
            cls.jobs.pop(0)()


class Pane:
    WARNING_MESSAGE = 2
    messages = []

    @classmethod
    def showMessageDialog(cls, parent, text, title, level):
        if not Swing.edt:
            raise AssertionError('Dialog outside EDT')
        cls.messages.append(text)


class Table:
    selected = 0
    mapping = [0]

    def getSelectedRow(self): return self.selected
    def getRowCount(self): return len(self.mapping)
    def convertRowIndexToModel(self, row): return self.mapping[row]


class Service:
    def getHost(self): return 'example.test'
    def getPort(self): return 8443
    def getProtocol(self): return 'HTTPS'


class Label:
    def setText(self, text):
        if not Swing.edt:
            raise AssertionError('Label update outside EDT')
        self.text = text


class Callbacks:
    def __init__(self):
        self.sent, self.errors, self.output = [], [], []
        self.fail = False

    def sendToRepeater(self, *args):
        if self.fail:
            raise RuntimeError('mock API failure')
        self.sent.append(args)

    def printOutput(self, text): self.output.append(text)
    def printError(self, text): self.errors.append(text)


source = Path(__file__).resolve().parents[1] / 'jsonp_v.py'
tree = ast.parse(source.read_text(encoding='utf-8'))
cls = next(n for n in tree.body if isinstance(n, ast.ClassDef)
           and n.name == 'BurpExtender')
methods = [n for n in cls.body if isinstance(n, ast.FunctionDef)
           and n.name in ('send_selected_to_repeater', '_repeater_notice')]
namespace = dict(unicode=str, SwingUtilities=Swing, JOptionPane=Pane,
                 JavaException=Exception, traceback=traceback)
exec(compile(ast.Module(body=methods, type_ignores=[]), str(source), 'exec'), namespace)
Ext = type('Ext', (), {n.name: namespace[n.name] for n in methods})


class RepeaterTests(unittest.TestCase):
    def setUp(self):
        Swing.edt, Swing.jobs, Pane.messages = True, [], []
        self.ext = Ext()
        self.ext._table = Table()
        self.ext._callbacks = Callbacks()
        self.ext._repeater_status = Label()
        self.ext._repeater_sequence = 0
        self.ext._visible = [{'service': Service(), 'request': b'first'}]

    def test_https_and_captured_request_survive_clear(self):
        self.ext.send_selected_to_repeater()
        self.ext._visible = []
        Swing.drain()
        self.assertEqual(self.ext._callbacks.sent,
                         [('example.test', 8443, True, b'first', 'JSONP-1')])
        self.assertIn('JSONP-1', self.ext._repeater_status.text)

    def test_missing_selection_has_feedback(self):
        self.ext._table.selected = -1
        self.ext.send_selected_to_repeater()
        Swing.drain()
        self.assertEqual(self.ext._callbacks.sent, [])
        self.assertIn('Select', Pane.messages[-1])

    def test_sorted_view_maps_to_correct_request(self):
        self.ext._visible.append({'service': Service(), 'request': b'second'})
        self.ext._table.mapping = [1, 0]
        self.ext.send_selected_to_repeater()
        Swing.drain()
        self.assertEqual(self.ext._callbacks.sent[0][3], b'second')

    def test_double_click_row_overrides_prior_selection(self):
        self.ext._visible.append({'service': Service(), 'request': b'second'})
        self.ext._table.mapping = [0, 1]
        self.ext.send_selected_to_repeater(1)
        Swing.drain()
        self.assertEqual(self.ext._callbacks.sent[0][3], b'second')

    def test_api_failure_is_logged_and_displayed(self):
        self.ext._callbacks.fail = True
        self.ext.send_selected_to_repeater()
        Swing.drain()
        self.assertIn('mock API failure', self.ext._callbacks.errors[-1])
        self.assertIn('failed', Pane.messages[-1])

    def test_empty_request_does_not_reach_api(self):
        self.ext._visible[0]['request'] = b''
        self.ext.send_selected_to_repeater()
        Swing.drain()
        self.assertEqual(self.ext._callbacks.sent, [])
        self.assertTrue(self.ext._callbacks.errors)

    def test_off_edt_dispatch(self):
        Swing.edt = False
        self.ext.send_selected_to_repeater()
        self.assertEqual(self.ext._callbacks.sent, [])
        Swing.drain()
        self.assertEqual(len(self.ext._callbacks.sent), 1)

    def test_distinct_tab_names(self):
        self.ext.send_selected_to_repeater()
        self.ext.send_selected_to_repeater()
        Swing.drain()
        self.assertEqual([args[-1] for args in self.ext._callbacks.sent],
                         ['JSONP-1', 'JSONP-2'])
