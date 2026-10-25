import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from privacy_claim_audit.audit import PHRASES, audit
from privacy_claim_audit.cli import main


class AuditTests(unittest.TestCase):
    def check_repo(self, prose, source, rule=None, filename='src/app.py'):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text(prose)
            path = root / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(source)
            result = audit(root)
            self.assertEqual([f['rule'] for f in result['findings']], [rule] if rule else [])
            self.assertEqual(result['status'], 'FAIL' if rule else 'PASS')
            return result

    def test_good_fixture(self):
        result = audit(Path(__file__).parent / 'fixtures/good')
        self.assertEqual(result['status'], 'PASS')
        self.assertIn({'claim': 'fully offline', 'file': 'README.md'}, result['verified_claims'])

    def test_bad_fixture(self):
        result = audit(Path(__file__).parent / 'fixtures/bad')
        self.assertEqual([f['rule'] for f in result['findings']], ['offline-claim-false'])

    def test_local_endpoint(self):
        self.check_repo('your data never leaves your machine', 'url = "https://example.com"', 'local-only-claim-false')

    def test_telemetry(self):
        self.check_repo('no telemetry', 'import sentry_sdk', 'no-telemetry-claim-false')

    def test_analytics_call(self):
        self.check_repo('no telemetry', 'import requests\nrequests.post("https://posthog.com/capture")', 'no-telemetry-claim-false')

    def test_generic_network_not_telemetry(self):
        self.check_repo('no telemetry', 'import requests\nrequests.get("https://example.com")')

    def test_bare_analytics_url_not_call(self):
        self.check_repo('no telemetry', 'url = "https://posthog.com"')

    def test_host_suffix_not_analytics(self):
        self.check_repo('no telemetry', 'requests.post("https://posthog.com.evil.example")')

    def test_no_claim(self):
        self.check_repo('A Python utility', 'import requests')

    def test_docstring_endpoint(self):
        self.check_repo('local only', '"""See https://example.com"""\ndef f():\n    """https://example.com"""\n    pass')

    def test_comment_claim_not_counted(self):
        self.check_repo('Utility', '# fully offline\nimport requests')

    def test_word_boundary(self):
        self.check_repo('offlineness', 'import requests')

    def test_case_insensitive(self):
        self.check_repo('FULLY OFFLINE', 'import requests', 'offline-claim-false')

    def test_alias(self):
        self.check_repo('no telemetry', 'from requests import post as send\nsend("https://posthog.com")', 'no-telemetry-claim-false')

    def test_subprocess(self):
        self.check_repo('offline', 'import subprocess\nsubprocess.run(["curl", "https://example.com"])', 'offline-claim-false')

    def test_test_only(self):
        self.check_repo('offline', 'import requests', 'test-only-network', 'tests/helper.py')

    def test_test_prefix(self):
        self.check_repo('offline', 'import socket', 'test-only-network', 'test_app.py')

    def test_test_suffix(self):
        self.check_repo('local-only', 'import socket', 'test-only-network', 'app_test.py')

    def test_telemetry_test_does_not_contradict(self):
        self.check_repo('no telemetry', 'import sentry_sdk', filename='tests/app.py')

    def test_ignore(self):
        fixture = Path(__file__).parent / 'fixtures/bad'
        result = audit(fixture, {'offline-claim-false'})
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['verified_claims'], [])

    def test_top_level_doc(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'GUIDE.md').write_text('no network')
            (root / 'a.py').write_text('import socket')
            self.assertEqual(audit(root)['findings'][0]['file'], 'GUIDE.md')

    def test_nested_doc_not_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'docs').mkdir()
            (root / 'docs/a.md').write_text('offline')
            (root / 'a.py').write_text('import socket')
            self.assertEqual(audit(root)['status'], 'PASS')

    def test_skipped_dirs_and_unneeded_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('offline')
            (root / '.env').write_bytes(b'\xff')
            for name in ('.venv', '__pycache__', 'dist', '.git', 'demo.egg-info'):
                (root / name).mkdir()
                (root / name / 'a.py').write_text('invalid Python !')
            self.assertEqual(audit(root)['status'], 'PASS')

    def test_deterministic_sorting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('offline\nno telemetry\nlocal only')
            (root / 'a.py').write_text('import requests\nimport sentry_sdk')
            first = audit(root)
            self.assertEqual(first, audit(root))
            self.assertEqual([f['rule'] for f in first['findings']], sorted(f['rule'] for f in first['findings']))
            self.assertTrue(all('a.py:' in f['message'] for f in first['findings']))

    def invoke(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            try:
                code = main(args)
            except SystemExit as exc:
                code = exc.code
        return code, output.getvalue(), errors.getvalue()

    def test_cli_good_json(self):
        code, output, _ = self.invoke([str(Path(__file__).parent / 'fixtures/good'), '--json'])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(output)['verified_claims'])

    def test_cli_bad_json(self):
        code, output, _ = self.invoke([str(Path(__file__).parent / 'fixtures/bad'), '--json'])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output)['status'], 'FAIL')

    def test_cli_version(self):
        code, output, _ = self.invoke(['--version'])
        self.assertEqual((code, output.strip()), (0, '0.1.0'))

    def test_cli_unknown_argument(self):
        self.assertEqual(self.invoke(['--unknown'])[0], 1)

    def test_cli_invalid_threshold(self):
        self.assertEqual(self.invoke(['--fail-on', 'LOW'])[0], 1)

    def test_cli_missing_path(self):
        self.assertEqual(self.invoke(['/nonexistent/privacy-audit-fixture'])[0], 1)

    def test_cli_unknown_rule(self):
        self.assertEqual(self.invoke(['--ignore', 'unknown'])[0], 1)

    def test_cli_verbose(self):
        fixture = str(Path(__file__).parent / 'fixtures/good')
        self.assertNotIn('Verified:', self.invoke([fixture])[1])
        self.assertIn('Verified:', self.invoke([fixture, '--verbose'])[1])

    def test_cli_ignore(self):
        self.assertEqual(self.invoke([str(Path(__file__).parent / 'fixtures/bad'), '--ignore', 'offline-claim-false'])[0], 0)

    def test_cli_threshold(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'README.md').write_text('offline')
            (root / 'test_a.py').write_text('import socket')
            code, output, _ = self.invoke([directory, '--fail-on', 'HIGH'])
            self.assertEqual(code, 0)
            self.assertIn('MEDIUM test-only-network', output)
            self.assertEqual(self.invoke([directory])[0], 2)

    def test_invalid_python_usage_error(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'a.py').write_text('invalid !')
            self.assertEqual(self.invoke([directory])[0], 1)


def make_phrase_test(kind, phrase):
    def test(self):
        source = 'import sentry_sdk' if kind == 'no-telemetry-claim' else 'import requests'
        self.check_repo(phrase, source, kind + '-false')
    return test


for kind, phrases in PHRASES.items():
    for index, phrase in enumerate(phrases):
        setattr(AuditTests, 'test_phrase_{}_{}'.format(kind.replace('-', '_'), index), make_phrase_test(kind, phrase))


def make_import_test(module):
    def test(self):
        self.check_repo('offline', 'import ' + module, 'offline-claim-false')
    return test


for module in ('httpx', 'urllib.request', 'urllib3', 'aiohttp', 'socket', 'smtplib', 'ftplib', 'websocket', 'websockets', 'telnetlib'):
    setattr(AuditTests, 'test_import_' + module.replace('.', '_'), make_import_test(module))

def make_sdk_test(module):
    def test(self):
        self.check_repo('no telemetry', 'import ' + module, 'no-telemetry-claim-false')
    return test


for module in ('posthog', 'mixpanel', 'amplitude', 'segment', 'analytics', 'telemetry', 'datadog', 'newrelic', 'honeycomb', 'plausible'):
    setattr(AuditTests, 'test_sdk_' + module, make_sdk_test(module))


def make_call_test(source):
    def test(self):
        self.check_repo('offline', source, 'offline-claim-false')
    return test


for index, source in enumerate(('urlopen("https://example.com")', 'requests.put("https://example.com")', 'httpx.get("https://example.com")', 'httpx.post("https://example.com")', 'socket.connect(("localhost", 80))', 'smtplib.SMTP("localhost")', 'subprocess.run(["wget", "https://example.com"])')):
    setattr(AuditTests, 'test_call_{}'.format(index), make_call_test(source))

if __name__ == '__main__':
    unittest.main()
