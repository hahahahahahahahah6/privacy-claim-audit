"""Command line interface."""
import argparse
import json
import sys
from . import __version__
from .audit import RULES, audit


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, '{}: error: {}\n'.format(self.prog, message))


def main(argv=None):
    parser = Parser(prog='privacy-claim-audit')
    parser.add_argument('path', nargs='?', default='.')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--fail-on', choices=['HIGH', 'MEDIUM'], default='MEDIUM')
    parser.add_argument('--ignore', default='')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--version', action='version', version=__version__)
    args = parser.parse_args(argv)
    ignore = set(args.ignore.split(',')) - {''}
    if ignore - RULES:
        parser.error('unknown ignored rule: ' + ', '.join(sorted(ignore - RULES)))
    try:
        result = audit(args.path, ignore, args.fail_on)
    except (OSError, ValueError, SyntaxError, UnicodeError) as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        for finding in result['findings']:
            print('{severity} {rule} {file}:{line} {message}'.format(**finding))
        if args.verbose:
            for claim in result['verified_claims']:
                print('Verified: {claim} ({file})'.format(**claim))
        print(result['status'])
    return 2 if result['status'] == 'FAIL' else 0
