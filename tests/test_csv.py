"""Exercise the GUI's CSV cell serializer without loading Burp or Swing."""
import ast
import csv
import io
from pathlib import Path
import unittest


source = Path(__file__).resolve().parents[1] / 'jsonp_v.py'
tree = ast.parse(source.read_text(encoding='utf-8'))
cls = next(node for node in tree.body
           if isinstance(node, ast.ClassDef) and node.name == 'BurpExtender')
method = next(node for node in cls.body
              if isinstance(node, ast.FunctionDef) and node.name == '_csv')
namespace = {}
exec(compile(ast.Module(body=[method], type_ignores=[]), str(source), 'exec'),
     namespace)


class CsvTests(unittest.TestCase):
    def roundtrip(self, value):
        encoded = namespace['_csv'](None, value)
        return next(csv.reader(io.StringIO(encoded + '\r\n', newline='')))[0]

    def test_formula_prefixes_are_treated_as_text(self):
        for value in ('=1+1', '+1', '-1', '@SUM(1)', '  =1+1',
                      '\ttext', '\rtext', '\ntext'):
            with self.subTest(value=value):
                self.assertEqual(self.roundtrip(value), "'" + value)

    def test_regular_cells_are_preserved(self):
        for value in ('https://example.test/a', 'HIT', '200', '中文',
                      'a,b', 'a"b', 'a\nb', 'a\rb'):
            with self.subTest(value=value):
                self.assertEqual(self.roundtrip(value), value)

    def test_formula_with_csv_delimiters_remains_one_cell(self):
        value = '=SUM(1,2)'
        encoded = namespace['_csv'](None, value)
        self.assertEqual(next(csv.reader(io.StringIO(encoded))),
                         ["'" + value])


if __name__ == '__main__':
    unittest.main()
