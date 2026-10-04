#!/usr/bin/env python3
"""Durable controller proof on reserved stage2 instance in localhost CHR."""
import json
import pathlib
import subprocess
from chr_dataplane import ROOT, rest

BIN = ROOT / '.cache/bin/controller-lab'
JOURNAL = ROOT / '.cache/controller-e2e'


def owned():
    return [r for r in rest('GET', 'ip/route')
            if r.get('comment') == 'mikrocentauri:stage2:route:canary']


def run(*args, expected=0):
    result = subprocess.run([str(BIN), '-journal', str(JOURNAL), *args],
                            cwd=ROOT, capture_output=True, text=True, timeout=40)
    assert result.returncode == expected, result.stderr
    return (result.stdout + result.stderr).strip()


if __name__ == '__main__':
    assert not owned(), 'Reserved disposable canary must initially be absent'
    BIN.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(ROOT/'.cache/go/bin/go'), 'build', '-o', str(BIN), './lab/controller'],
                   cwd=ROOT, check=True)
    run('-action', 'recover')
    fault = run('-action', 'apply', '-lose-reply', expected=1)
    pending = json.loads((JOURNAL/'journal.json').read_text())
    assert pending['state'] == 'pending' and len(owned()) == 1
    assert owned()[0]['disabled'] == 'true'
    run('-action', 'recover')  # independent process and transport
    assert not owned()
    assert json.loads((JOURNAL/'journal.json').read_text())['state'] == 'rolled-back'
    create = run('-action', 'apply')
    update = run('-action', 'apply', '-distance', '2')
    assert owned()[0]['distance'] == '2'
    noop = run('-action', 'apply', '-distance', '2')
    assert noop.endswith('0')
    cleanup = run('-action', 'cleanup')
    assert not owned()
    assert JOURNAL.stat().st_mode & 0o777 == 0o700
    assert (JOURNAL/'journal.json').stat().st_mode & 0o777 == 0o600
    result = {'lost_create_reply': fault, 'new_process_recovery': 'PASS',
              'create': create, 'update': update, 'idempotence': noop, 'cleanup': cleanup,
              'private_journal_permissions': '0700/0600', 'scope': 'disabled route only; reserved stage2'}
    (ROOT/'.cache/dataplane/controller-results.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))
