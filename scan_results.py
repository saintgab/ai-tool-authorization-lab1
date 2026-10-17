"""Report candidate filenames only; never echo matching secret material."""
import argparse
import re
from pathlib import Path

KEY_PATTERN = re.compile(rb'\bsk-(?:(?:proj|svcacct)-)?[A-Za-z0-9_-]{20,}')


def scan(root):
    literal, shaped = [], []
    for path in sorted(root.rglob('*')):
        if not path.is_file():
            continue
        data = path.read_bytes()
        if b'sk-' in data:
            literal.append(str(path))
        if KEY_PATTERN.search(data):
            shaped.append(str(path))
    return literal, shaped


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('directory', nargs='?', default='results')
    args = parser.parse_args()
    root = Path(args.directory)
    if not root.is_dir():
        parser.error('Directory not found')
    literal, shaped = scan(root)
    print('Literal sk- candidate files (may include harmless task-scope labels):')
    print('\n'.join(literal) or 'None')
    print('API-key-shaped candidate files (review privately before sharing):')
    print('\n'.join(shaped) or 'None')
    print('No matching text or secret value was printed. Pattern scans are not proof of absence.')
    return 1 if shaped else 0


if __name__ == '__main__':
    raise SystemExit(main())
