#!/usr/bin/env python3
"""Disposable Linux PTY role controls; no installed services or real identities.
Requires the sync_chain.py dependencies and pyte. Uses repository-built binaries.
"""
import fcntl
import json
import os
import pty
import select
import struct
import subprocess
import tempfile
import termios
import sys
from pathlib import Path

import pyte
sys.dont_write_bytecode = True
import sync_chain as chain


class Terminal:
    def __init__(self, data):
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 180, 0, 0))
        self.screen = pyte.Screen(180, 40)
        self.stream = pyte.ByteStream(self.screen)
        self.process = subprocess.Popen([str(chain.BIN/'wayfinder'), '--data-dir', str(data), 'tui'],
                                        stdin=self.slave, stdout=self.slave, stderr=self.slave,
                                        env={**os.environ, 'TERM': 'xterm-256color'})

    def text(self):
        while select.select([self.master], [], [], .01)[0]:
            self.stream.feed(os.read(self.master, 65536))
        return '\n'.join(self.screen.display)

    def send(self, text):
        os.write(self.master, text.encode())

    def expect(self, text):
        chain.wait(lambda: text in self.text(), timeout=20)

    def click(self, label):
        self.expect(label)
        for y, line in enumerate(self.screen.display):
            x = line.find(label)
            if x >= 0:
                self.send(f'\x1b[<0;{x+1};{y+1}M\x1b[<0;{x+1};{y+1}m')
                return
        raise AssertionError('Missing target ' + label)

    def close(self):
        if self.process.poll() is None:
            self.send('\x03')
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        os.close(self.master)
        os.close(self.slave)


def run():
    terminals = []
    try:
        with tempfile.TemporaryDirectory(prefix='wayfinder-role-tui-') as tmp:
            root = Path(tmp)
            origin = f'http://127.0.0.1:{chain.port()}'
            chain.spawn([chain.BIN/'wayfinder-gateway', '--listen', origin.removeprefix('http://'),
                         '--public-url', origin, '--data-dir', root/'gateway'])
            chain.wait(lambda: chain.http(origin, '/.well-known/oauth-authorization-server')[0] == 200)
            phrase = chain.Mnemonic('english').generate(strength=256)
            for name, admin in [('root-admin', True), ('PVE-Lab', False)]:
                runtime = root/('runtime-'+name)
                runtime.mkdir(mode=0o700)
                os.environ['XDG_RUNTIME_DIR'] = str(runtime)
                data, identity, process = chain.enroll(root, name, phrase, origin, admin)
                if admin:
                    a, ia, pa = data, identity, process
                else:
                    b, ib, pb = data, identity, process
            os.environ['XDG_RUNTIME_DIR'] = str(root/'runtime-root-admin')
            admin_ui = Terminal(a)
            terminals.append(admin_ui)
            admin_ui.expect('gateway confirmed')
            os.environ['XDG_RUNTIME_DIR'] = str(root/'runtime-PVE-Lab')
            member_ui = Terminal(b)
            terminals.append(member_ui)
            member_ui.expect('member (gateway confirmed)')
            member_ui.click('Browser pairing')
            member_ui.expect('requires an administrative device')
            admin_ui.click('Devices')
            admin_ui.click('PVE-Lab')
            admin_ui.expect('[ Promote to Admin (P) ]')
            admin_ui.click('[ Promote to Admin (P) ]')
            admin_ui.expect('Current gateway-confirmed role: member')
            chain.check('TUI promotion waits for explicit confirmation', chain.operation(ib, origin, dict(operation='grants'))[0] == 403)
            # Confirmation requires typing yes, as revocation does.
            admin_ui.send('yes\r')
            member_ui.expect('Approve a browser pairing request')
            chain.check('promoted Member gains pairing controls in open TUI', pb.poll() is None)
            status, _, client = chain.http(origin, '/oauth/register', dict(
                client_name='Disposable TUI pairing', redirect_uris=['http://127.0.0.1:19876/callback'],
                token_endpoint_auth_method='none'))
            assert status == 201
            ticket, code, _ = chain.start_auth(origin, client)
            member_ui.send('\r')
            member_ui.expect('Pairing code from your browser')
            member_ui.send(code+'\r')
            member_ui.expect('Client is self-reported')
            member_ui.send('yes\r')
            member_ui.expect('Approved. Refresh the browser authorization page.')
            chain.check('newly promoted Member directly approves OAuth in its existing TUI', chain.http(origin, ticket)[0] == 303)
            member_ui.click('Devices')
            member_ui.expect('[ Revoke selected (D) ]')
            chain.check('promoted Member gains device controls in open TUI', True)
            # The root device's own selected row must never offer demotion.
            admin_ui.expect('[ Demote to Member (M) ]')
            admin_ui.click('[ Demote to Member (M) ]')
            admin_ui.expect('Current gateway-confirmed role: admin')
            admin_ui.send('yes\r')
            chain.wait(lambda: '[ Revoke selected (D) ]' not in member_ui.text(), timeout=20)
            member_ui.send('r')
            member_ui.click('Browser pairing')
            member_ui.expect('requires an administrative device')
            chain.check('demoted TUI loses device and pairing controls after refresh', pb.poll() is None)
            chain.check('TUI changes preserve installation and connected Member function',
                        json.loads((b/'installation.json').read_text()) == ib and
                        chain.operation(ib, origin, dict(operation='devices'))[0] == 200)
            for terminal in terminals:
                terminal.close()
            terminals.clear()
            # Offline status must never fall back to the immutable Admin certificate.
            for process in chain.processes:
                if process.poll() is None:
                    process.terminate()
            for process in chain.processes:
                process.wait(timeout=10)
            result = subprocess.run([str(chain.BIN/'wayfinder'), '--data-dir', str(a), 'status'], capture_output=True, check=True)
            status = json.loads(result.stdout)
            chain.check('offline status distinguishes certificate authority from unconfirmed effective role',
                        status['role'] is None and status['role_status'] == 'unconfirmed' and status['certificate_role'] == 'admin')
    finally:
        for terminal in terminals:
            terminal.close()
        for process in chain.processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
    print(f'{len(chain.checks)} TUI role checks passed; no secrets printed')


if __name__ == '__main__':
    run()
