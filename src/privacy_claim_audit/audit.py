"""Read only Markdown documentation and Python source; never execute targets."""
import ast
import os
from pathlib import Path
import re

PHRASES = {
    'offline-claim': ('offline', 'works offline', 'fully offline', 'no internet', 'no network', 'no network access', 'does not require internet', 'no internet required'),
    'local-only-claim': ('local only', 'local-only', 'runs locally', 'stays on your machine', 'never leaves your machine', 'data never leaves', 'your data stays'),
    'no-telemetry-claim': ('no telemetry', 'no tracking', 'no analytics', 'no phone home', 'no data collection', 'does not collect', 'does not send', 'does not transmit', 'does not upload', 'does not phone home'),
}
NETWORK = {'requests', 'httpx', 'urllib3', 'aiohttp', 'socket', 'smtplib', 'ftplib', 'websocket', 'websockets', 'telnetlib'}
TELEMETRY = {'sentry_sdk', 'posthog', 'mixpanel', 'amplitude', 'segment', 'analytics', 'telemetry', 'datadog', 'newrelic', 'honeycomb', 'plausible'}
HOSTS = ('segment.io', 'amplitude.com', 'mixpanel.com', 'posthog.com', 'sentry.io', 'google-analytics.com', 'googletagmanager.com')
ENDPOINT = re.compile(r'https?://[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
ANALYTICS = re.compile(r'https?://(?:[A-Za-z0-9-]+\.)*(?:' + '|'.join(re.escape(h) for h in HOSTS) + r')(?=[:/\s?#]|$)', re.I)
SKIP = {'.venv', 'venv', '__pycache__', 'dist', '.git', 'build'}
RULES = {'offline-claim-false', 'local-only-claim-false', 'no-telemetry-claim-false', 'test-only-network'}


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return dotted(node.value) + '.' + node.attr
    return ''


def evidence(path):
    tree = ast.parse(path.read_text(encoding='utf-8'), filename=str(path))
    aliases = {}
    found = []
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                docstrings.add(id(first.value))
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for item in node.names:
                name = item.name if isinstance(node, ast.Import) else (node.module or '') + '.' + item.name
                aliases[item.asname or (item.name.split('.')[0] if isinstance(node, ast.Import) else item.name)] = name if item.asname or isinstance(node, ast.ImportFrom) else item.name.split('.')[0]
                top = name.split('.')[0]
                if top in NETWORK or name == 'urllib.request' or name.startswith('urllib.request.'):
                    found.append(('network-import', node.lineno))
                if top in TELEMETRY:
                    found.append(('telemetry-import', node.lineno))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings and ENDPOINT.search(node.value):
            found.append(('hardcoded-endpoint', node.lineno))
        if not isinstance(node, ast.Call):
            continue
        name = dotted(node.func)
        head, _, tail = name.partition('.')
        name = aliases.get(head, head) + ('.' + tail if tail else '')
        network = name in {'urlopen', 'urllib.request.urlopen', 'requests.get', 'requests.post', 'requests.put', 'httpx.get', 'httpx.post', 'socket.socket', 'socket.connect', 'smtplib.SMTP'}
        if name.startswith('subprocess.'):
            network |= any(isinstance(arg, ast.Constant) and arg.value in ('curl', 'wget') for value in node.args for arg in ast.walk(value))
        if network:
            found.append(('network-call', node.lineno))
            if any(isinstance(arg, ast.Constant) and isinstance(arg.value, str) and ANALYTICS.search(arg.value) for arg in ast.walk(node)):
                found.append(('analytics-call', node.lineno))
    return sorted(set(found), key=lambda x: (x[1], x[0]))


def audit(root, ignore=(), fail_on='MEDIUM'):
    root = Path(root)
    if not root.is_dir():
        raise ValueError('path must be a project directory')
    claims = []
    for path in sorted(root.glob('*.md')):
        if path.is_symlink():
            continue
        text = path.read_text(encoding='utf-8')
        for kind, phrases in PHRASES.items():
            pattern = r'\b(?:' + '|'.join(re.escape(p) for p in sorted(phrases, key=len, reverse=True)) + r')\b'
            for match in re.finditer(pattern, text, re.I):
                claims.append((kind, match.group().lower(), path.name, text.count('\n', 0, match.start()) + 1))
    production, tests = [], []
    paths = []
    for directory, names, files in os.walk(root, followlinks=False):
        names[:] = sorted(name for name in names if name not in SKIP and not name.endswith('.egg-info') and not (Path(directory) / name).is_symlink())
        paths.extend(Path(directory) / name for name in files if name.endswith('.py') and not (Path(directory) / name).is_symlink())
    for path in sorted(paths):
        relative = path.relative_to(root)
        is_test = 'tests' in relative.parts or path.name.startswith('test_') or path.name.endswith('_test.py')
        for kind, line in evidence(path):
            if is_test and kind == 'hardcoded-endpoint':
                continue
            (tests if is_test else production).append((kind, relative.as_posix(), line))
    production.sort(key=lambda e: (e[1], e[2], e[0]))
    tests.sort(key=lambda e: (e[1], e[2], e[0]))
    findings, verified = [], []
    accepted = {
        'offline-claim': {'network-import', 'network-call'},
        'local-only-claim': {'network-import', 'network-call', 'hardcoded-endpoint'},
        'no-telemetry-claim': {'telemetry-import', 'analytics-call'},
    }
    for kind, phrase, doc, line in claims:
        relevant = [e for e in production if e[0] in accepted[kind]]
        rule = kind + '-false'
        severity = 'HIGH'
        if not relevant and kind != 'no-telemetry-claim' and tests and not production:
            relevant = tests
            rule, severity = 'test-only-network', 'MEDIUM'
        if relevant:
            first = relevant[0]
            if rule not in ignore:
                findings.append(dict(severity=severity, rule=rule, file=doc, line=line,
                                     message="Claim '{}' in {} conflicts with {} at {}:{}".format(phrase, doc, first[0], first[1], first[2])))
        else:
            item = dict(claim=phrase, file=doc)
            if item not in verified:
                verified.append(item)
    findings.sort(key=lambda f: (f['rule'], f['file'], f['line'], f['message']))
    failed = any(f['severity'] == 'HIGH' or fail_on == 'MEDIUM' for f in findings)
    return dict(status='FAIL' if failed else 'PASS', findings=findings, verified_claims=sorted(verified, key=lambda c: (c['file'], c['claim'])))
