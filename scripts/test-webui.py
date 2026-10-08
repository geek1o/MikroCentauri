#!/usr/bin/env python3
"""Run real HTTPS/browser contracts against an explicitly simulated runtime."""
import argparse
import json
import os
from pathlib import Path
import selectors
import shutil
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--install-browsers', action='store_true')
    p.add_argument('--project', choices=['chromium', 'firefox', 'webkit'])
    p.add_argument('--all-browsers', action='store_true', help='also run the optional Firefox project')
    p.add_argument('--headed', action='store_true',help='run the disposable test browser with a window')
    p.add_argument('--node', default=os.environ.get('WEB_UI_NODE','node'), help='Node executable for browser tooling')
    args = p.parse_args()
    binary = ROOT/'.cache/bin/webui-fixture'
    binary.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(ROOT/'.cache/go/bin/go'), 'build', '-o', str(binary), './tests/e2e/webui/fixture'], cwd=ROOT, check=True)
    cwd = ROOT/'tests/e2e/webui'
    node = shutil.which(args.node)
    if not node: raise RuntimeError('Node executable not found')
    tool_env = dict(os.environ,PATH=str(Path(node).parent)+os.pathsep+os.environ.get('PATH',''))
    subprocess.run(['npm', 'ci', '--no-audit', '--no-fund'], cwd=cwd, env=tool_env,check=True)
    if args.install_browsers:
        subprocess.run([node, str(cwd/'node_modules/playwright/cli.js'), 'install', 'chromium', 'firefox', 'webkit'], cwd=cwd, env=tool_env, check=True)
    arch = {'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine(),platform.machine())
    sb = ROOT/f'.cache/sing-box-1.14.2-{platform.system().lower()}-{arch}/sing-box'
    sb = Path(os.environ.get('SING_BOX_BINARY', str(sb)))
    projects = [args.project] if args.project else ['chromium', 'webkit'] + (['firefox'] if args.all_browsers else [])
    # Each browser gets fresh private state and its own authentication budget.
    for project in projects:
        proc = subprocess.Popen([str(binary), '-sing-box', str(sb)], cwd=ROOT, text=True, stdout=subprocess.PIPE)
        try:
            selector = selectors.DefaultSelector()
            selector.register(proc.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=30):
                raise RuntimeError('HTTPS fixture startup timeout')
            data = json.loads(proc.stdout.readline())
            env = dict(tool_env, WEB_UI_URL=data['url'], WEB_UI_LIST_URL=data.get('list_url',''))
            cmd = [node, str(cwd/'node_modules/playwright/cli.js'), 'test', '--project', project]
            if args.headed: cmd += ['--headed']
            subprocess.run(cmd, cwd=cwd, env=env, check=True)
        finally:
            selector.close()
            proc.terminate()
            try: proc.wait(timeout=10)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait()

if __name__ == '__main__': main()
