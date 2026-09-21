#!/usr/bin/env python3
"""Linux PTY mouse, terminal cleanup and ownership regression.

Requires pyte, a running user service manager, and repository-built wayfinder and
wayfinder-gateway binaries. Installs only a uniquely named disposable service.
Recovery material is kept in memory; all service/data resources are cleaned up.
Run: python3 tests/tui_service.py
"""
import pyte
import base64, re, urllib.request, urllib.parse, urllib.error, signal, threading, http.server
import fcntl, hashlib, json, os, pathlib, pty, select, shutil, socket, struct, subprocess, tempfile, termios, time

REPO = pathlib.Path(__file__).resolve().parents[1]
BIN = REPO / 'target/debug/wayfinder'
GATEWAY = REPO / 'target/debug/wayfinder-gateway'
checks = []

def check(label, condition=True):
    assert condition, label
    checks.append(label)
    print('PASS', label, flush=True)

def wait(fn, label, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if fn():
            return
        time.sleep(.05)
    raise AssertionError('Timed out: ' + label)

def run(args, ok=True):
    p = subprocess.run([str(a) for a in args], capture_output=True, timeout=25)
    if ok and p.returncode:
        raise AssertionError('Command failed: ' + str(args[0]) + ': ' + p.stderr.decode())
    return p

class Terminal:
    def __init__(self, args):
        self.master, self.slave = pty.openpty()
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', 40, 240, 0, 0))
        self.before = termios.tcgetattr(self.slave)
        self.output = b''
        self.screen = pyte.Screen(240, 40)
        self.stream = pyte.ByteStream(self.screen)
        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(self.slave, termios.TIOCSCTTY, 0)
        self.proc = subprocess.Popen([str(a) for a in args], stdin=self.slave, stdout=self.slave, stderr=self.slave, preexec_fn=controlling_terminal, env={**os.environ, 'TERM':'xterm-256color'})
        terminals.append(self)
    def read(self):
        while select.select([self.master], [], [], .01)[0]:
            chunk = os.read(self.master, 65536)
            self.output += chunk
            self.stream.feed(chunk)
        return '\n'.join(self.screen.display)
    def expect(self, text):
        wait(lambda: ''.join(text.split()) in ''.join(self.read().split()), text)
    def send(self, text):
        os.write(self.master, text.encode())
    def mouse(self, x, y, button=0):
        self.send(f'\x1b[<{button};{x+1};{y+1}M')
        if button == 0:
            self.send(f'\x1b[<0;{x+1};{y+1}m')
        time.sleep(.15)
        self.read()
    def click(self, label):
        self.expect(label)
        for y, line in enumerate(self.screen.display):
            x = line.find(label)
            if label in ('Overview', 'Devices', 'MCP Grants', 'Browser pairing', 'Gateway', 'Agent', 'Updates', 'Create Sync Chain', 'Join Sync Chain') and (y < 4 or x >= 22):
                continue
            if x >= 0:
                self.mouse(x, y)
                return
        raise AssertionError('No clickable label: ' + label)
    def resize(self, width, height):
        self.screen.resize(height, width)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack('HHHH', height, width, 0, 0))
        os.kill(self.proc.pid, signal.SIGWINCH)
        time.sleep(.2)
        self.read()
    def action(self, key):
        self.read()
        self.output = b''
        self.click({'s':'[ Start (S) ]', 'x':'[ Stop (X) ]', 't':'[ Restart (T) ]', 'i':'[ Install automatic startup (I) ]', 'u':'[ Uninstall automatic startup (U) ]'}[key])
        self.expect('Type yes, then Enter to confirm')
        self.send('yes')
        self.click('[ Confirm ]')
        wait(lambda: 'Type yes, then Enter to confirm' not in self.read(), 'confirmation submitted')
    def quit(self, key=None):
        if key is None:
            self.click('[ Quit (Q) ]')
        else:
            self.send(key)
        wait(lambda: (self.read(), self.proc.poll() is not None)[1], 'TUI exit')
        check('terminal attributes and screen/paste/mouse modes restored', self.proc.returncode == 0 and termios.tcgetattr(self.slave) == self.before and b'\x1b[?1049l' in self.output and b'\x1b[?2004l' in self.output and all(f'\x1b[?{mode}l'.encode() in self.output for mode in (1000,1002,1003,1015,1006)))
        self.close()
    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=15)
        if self.master is not None:
            os.close(self.master)
            os.close(self.slave)
            self.master = None

def fault_audit(root, data):
    """Loopback fault injection: stalled lookup and malformed list response."""
    release = threading.Event()
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))) or b'{}')
            if self.path.split('?')[0] == '/device/challenge':
                result = dict(version=1, gateway=origin, nonce='disposable-challenge')
            else:
                if body['operation']['operation'] == 'pending':
                    release.wait(5)
                result = {}  # Deliberately invalid list; session must unwind through Restore.
            raw = json.dumps(result).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            try: self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError): pass
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    origin = f'http://127.0.0.1:{server.server_port}'
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    fault = root/'fault'
    fault.mkdir(mode=0o700)
    identity = json.loads((data/'installation.json').read_text())
    identity['gateway'] = origin
    (fault/'installation.json').write_text(json.dumps(identity))
    (fault/'installation.json').chmod(0o600)
    try:
        t = Terminal([BIN, '--data-dir', fault, 'tui'])
        t.expect('Temporary agent')
        t.click('Browser pairing')
        t.click('[ Look up pairing code (Enter) ]')
        t.send('AAAA-BBBB')
        t.click('[ Continue ]')
        t.expect('Working')
        t.click('[ Cancel ]')
        t.expect('Lookup canceled')
        check('busy pairing lookup remains mouse-cancellable')
        release.set()
        t.click('Devices')
        wait(lambda: (t.read(), t.proc.poll() is not None)[1], 'malformed gateway error exit')
        check('error exit restores raw, screen, paste and mouse modes', t.proc.returncode != 0 and termios.tcgetattr(t.slave) == t.before and all(f'\x1b[?{mode}l'.encode() in t.output for mode in (1049,2004,1000,1002,1003,1015,1006)))
        t.close()
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join()

def mouse_audit(root, data, origin, phrase):
    t = Terminal([BIN, '--data-dir', root/'create', 'tui'])
    t.expect('Welcome to Wayfinder')
    check('mouse capture enabled', all(f'\x1b[?{mode}h'.encode() in t.output for mode in (1000,1002,1003,1015,1006)))
    t.click('Join Sync Chain')
    t.expect('[ Join Sync Chain ]')
    t.click('Create Sync Chain')
    t.click('[ Create Sync Chain ]')
    t.send('created-with-mouse')
    t.click('[ Continue ]')
    t.send(origin)
    t.click('[ Continue ]')
    t.expect('Store these 24 recovery words')
    t.click("[ I've stored it ]")
    t.expect('Have you stored the recovery phrase')
    t.click('[ Confirm ]')
    t.expect('Explicit confirmation requires typing yes')
    t.click('[ Cancel ]')
    check('Create keeps explicit storage confirmation')
    t.quit('q')
    t = Terminal([BIN, '--data-dir', root/'member', 'tui'])
    t.expect('Welcome to Wayfinder')
    t.click('Join Sync Chain')
    t.click('[ Join Sync Chain ]')
    t.send('mouse-member')
    t.click('[ Continue ]')
    t.send(origin)
    t.click('[ Continue ]')
    t.click('[ Continue ]')
    t.expect('24 recovery words (hidden)')
    t.output = b''
    t.send('\x1b[200~' + phrase + '\x1b[201~')
    time.sleep(.2)
    t.read()
    check('join paste is masked', '*' in t.read())
    t.send('\x1bOQ')
    time.sleep(.2)
    check('join phrase can be revealed', phrase in t.read() and 'F2 hide' in t.read())
    t.send('\x1bOQ')
    time.sleep(.2)
    check('join phrase can be hidden again', phrase not in t.read() and '*' in t.read())
    t.click('[ Join ]')
    t.expect('Action completed')
    t.quit('\x03')
    t = Terminal([BIN, '--data-dir', data, 'tui'])
    t.expect('Temporary agent')
    for section, expected in [('Devices','entries'),('MCP Grants','entries'),('Browser pairing','Approve a browser'),('Gateway','Current gateway'),('Agent','Automatic startup installed'),('Updates','Source/package-manager'),('Overview','Device ID')]:
        t.click(section)
        t.expect(expected)
    check('all seven sections clickable')
    t.click('Devices')
    t.expect('2 entries')
    t.click('mouse-member')
    t.expect('name: mouse-member')
    # Wheel over list changes selection without scrolling details.
    t.mouse(25, 5, 65)
    t.mouse(25, 5, 64)
    check('list wheel changes selected row', any('›' in line[22:] for line in t.screen.display))
    t.click('mouse-member')
    t.resize(80, 24)
    t.expect('mouse-member')
    before = t.read()
    t.mouse(26, 16, 65)
    check('details wheel scrolls independently', before != t.read())
    t.click('[ Revoke selected (D) ]')
    t.expect('Permanently revoke')
    t.mouse(3, 9) # underlying Agent/section position is covered by modal
    t.expect('Permanently revoke')
    t.click('[ Confirm ]')
    t.expect('Explicit confirmation requires typing yes')
    t.click('[ Cancel ]')
    t.expect('[ Revoke selected (D) ]')
    check('revoke requires yes, Cancel works, modal prevents click-through')
    t.click('[ Revoke selected (D) ]')
    t.send('yes')
    t.click('[ Confirm ]')
    t.expect('Action completed')
    t.click('[ Refresh (R) ]')
    t.expect('REVOKED')
    check('yes plus mouse Confirm revokes selected device; Refresh reloads')
    t.resize(240, 40)
    t.click('Gateway')
    t.expect('Current gateway')
    before = (data/'installation.json').read_bytes()
    t.click('[ Migrate this device (M) ]')
    t.expect('Destination gateway URL')
    t.send('https://migration.invalid\r')
    t.expect('Type yes')
    t.send('no\r')
    t.expect('Explicit confirmation requires typing yes')
    t.send('\x7f\x7fyes\r')
    t.expect('24 recovery words (hidden)')
    t.send('private-migration-secret')
    time.sleep(.2)
    check('migration phrase is masked', '*' in t.read())
    t.send('\x1b')
    check('migration cancellation preserves installation', (data/'installation.json').read_bytes()==before)
    t.click('[ Migrate this device (M) ]')
    t.send('https://migration.invalid\r')
    t.send('yes\r')
    t.expect('24 recovery words (hidden)')
    t.send('invalid recovery words\r')
    t.expect('Invalid 24-word')
    wait(locked, 'temporary agent restored after migration failure')
    check('failed migration preserves installation and restores temporary agent', (data/'installation.json').read_bytes()==before)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        destination=f'http://127.0.0.1:{sock.getsockname()[1]}'
    target = subprocess.Popen([str(GATEWAY), '--listen', destination.removeprefix('http://'), '--public-url', destination, '--data-dir', str(root/'migration-gateway')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        def destination_ready():
            try:
                return urllib.request.urlopen(destination+'/.well-known/oauth-authorization-server').status==200
            except OSError:
                return False
        wait(destination_ready, 'migration gateway')
        for url in (destination, origin):
            t.click('[ Migrate this device (M) ]')
            t.send(url+'\r')
            t.send('yes\r')
            t.expect('24 recovery words (hidden)')
            t.output=b''
            t.send('\x1b[200~'+phrase+'\x1b[201~')
            t.read()
            time.sleep(.2)
            check('migration paste is masked', '*' in t.read())
            t.click('[ Migrate ]')
            t.expect('This device migrated')
            expected={**json.loads(before),'gateway':url}
            check('TUI migration preserves same device identity', json.loads((data/'installation.json').read_text())==expected)
            wait(lambda: run([BIN, '--data-dir', data, 'devices'], ok=False).returncode==0, 'migrated temporary agent reconnects')
    finally:
        target.terminate();target.wait(timeout=15)
    t.click('Updates')
    t.click('[ Install update (I) ]')
    check('unavailable update cannot open confirmation', 'Type yes' not in t.read())
    t.click('[ Check for updates (C) ]')
    t.expect('Checking release channel')
    check('update check clickable')
    # Exercise real browser OAuth review and grant creation through mouse approval.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args): return None
    opener = urllib.request.build_opener(NoRedirect)
    def http(path, body=None, form=False):
        raw = None if body is None else (urllib.parse.urlencode(body) if form else json.dumps(body)).encode()
        req = urllib.request.Request(origin+path, raw, {'Content-Type':'application/x-www-form-urlencoded' if form else 'application/json'})
        try: response = opener.open(req, timeout=10)
        except urllib.error.HTTPError as e: response = e
        with response:
            return response.status, response.headers, response.read().decode()
    status, _, raw = http('/oauth/register', dict(client_name='Mouse MCP',redirect_uris=['http://127.0.0.1:19876/callback'],token_endpoint_auth_method='none'))
    assert status == 201
    client = json.loads(raw)
    verifier = 'v'*43
    query = dict(response_type='code',client_id=client['client_id'],redirect_uri=client['redirect_uris'][0],scope='read exec',state='mouse-audit',resource=origin,code_challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('='),code_challenge_method='S256')
    status, headers, _ = http('/oauth/authorize?'+urllib.parse.urlencode(query))
    assert status == 303
    ticket = headers['Location']
    _, _, page = http(ticket)
    code = re.search(r'wayfinder authorize ([A-F0-9]+-[A-F0-9]+)', page)[1]
    t.click('Browser pairing')
    t.click('[ Look up pairing code (Enter) ]')
    t.send(code)
    t.click('[ Continue ]')
    t.expect('Mouse MCP')
    t.expect('redirect uri:')
    t.expect('read, exec')
    before = t.read()
    t.mouse(30, 8, 65)
    check('modal wheel scrolls review content', before != t.read())
    t.mouse(30, 8, 64)
    t.click('[ Confirm ]')
    t.expect('Explicit confirmation requires typing yes')
    t.send('yes')
    t.click('[ Confirm ]')
    t.expect('Approved')
    _, headers, _ = http(ticket)
    authcode = urllib.parse.parse_qs(urllib.parse.urlparse(headers['Location']).query)['code'][0]
    assert http('/oauth/token', dict(grant_type='authorization_code',client_id=client['client_id'],code=authcode,redirect_uri=client['redirect_uris'][0],resource=origin,code_verifier=verifier), True)[0] == 200
    t.click('MCP Grants')
    t.expect('1 entries')
    t.click('Mouse MCP')
    t.expect('name: Mouse MCP')
    t.click('[ Revoke selected (D) ]')
    t.click('[ Cancel ]')
    t.click('[ Revoke selected (D) ]')
    t.send('yes')
    t.click('[ Confirm ]')
    t.expect('Action completed')
    t.click('[ Refresh (R) ]')
    t.expect('REVOKED')
    check('OAuth review, exact confirmation, grant row and revoke work by mouse')
    t.send('\t\x1b[A')
    t.expect('Devices • Tab')
    t.send('\t\x1b[B')
    check('keyboard navigation still available')
    t.quit()

terminals = []
gateway = external = None
unit = definition = dropin = None
with tempfile.TemporaryDirectory(prefix='wayfinder-service-audit-') as tmp:
    root = pathlib.Path(tmp)
    data = root / 'agent'
    def cli(*args):
        return run([BIN, '--data-dir', data, *args])
    def systemctl(*args, ok=True):
        return run(['systemctl', '--user', *args], ok=ok)
    def state():
        p = systemctl('show', unit, '-p', 'ActiveState', '-p', 'SubState', '-p', 'MainPID', '-p', 'NRestarts')
        return dict(line.split('=', 1) for line in p.stdout.decode().splitlines())
    def active():
        s = state()
        return s['ActiveState'] == 'active' and s['SubState'] == 'running' and int(s['MainPID']) > 0
    def locked():
        with open(data / 'daemon.lock', 'a') as f:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return False
            except BlockingIOError:
                return True
    def tui(temporary=True):
        t = Terminal([BIN, '--data-dir', data, 'tui'])
        t.expect('Temporary agent' if temporary else 'Attached agent')
        wait(locked, 'agent holds lock')
        t.click('Agent')
        t.expect('Automatic startup installed')
        return t
    try:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'
        gateway = subprocess.Popen([str(GATEWAY), '--listen', f'127.0.0.1:{port}', '--public-url', origin, '--data-dir', str(root / 'gateway')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def ready():
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.2):
                    return True
            except OSError:
                return False
        wait(ready, 'loopback gateway')
        enrollment = Terminal([BIN, '--data-dir', data, 'chain', 'create', '--name', 'disposable-tui-audit', '--gateway', origin])
        enrollment.expect('Type yes:')
        # Disposable recovery output stays in memory and is discarded, never logged.
        phrase = next(line.strip() for line in enrollment.screen.display if re.fullmatch(r'[a-z]+(?: [a-z]+){23}', line.strip()))
        enrollment.send('yes\r')
        wait(lambda: (enrollment.read(), enrollment.proc.poll() is not None)[1], 'enrollment')
        check('disposable identity enrolled against loopback gateway', enrollment.proc.returncode == 0)
        enrollment.output = b''
        enrollment.close()
        cache = data / 'update-check.json'
        cache.write_text(json.dumps({'checked':int(time.time()), 'latest':None, 'error':'local lifecycle audit'}))
        cache.chmod(0o600)
        fault_audit(root, data)
        mouse_audit(root, data, origin, phrase)
        del phrase
        unit = 'app.usewayfinder.agent.' + hashlib.sha256(str(data.resolve()).encode()).hexdigest()[:16] + '.service'
        definition = pathlib.Path(os.environ.get('XDG_CONFIG_HOME', str(pathlib.Path.home()/'.config'))) / 'systemd/user' / unit
        cli('service', 'install')
        wait(active, 'installed service active')
        cli('service', 'stop')
        wait(lambda: not locked(), 'service stopped')
        probe = root / 'probe.py'
        marker = root / 'lock-released'
        failure = root / 'fail'
        break_identity = root / 'break-identity'
        probe.write_text('import fcntl, pathlib, sys, time\nr=pathlib.Path(__file__).parent\nif (r/"slow").exists(): time.sleep(3)\nwith open(r/"agent/daemon.lock", "a") as f:\n fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB)\n (r/"lock-released").write_text("released")\nif (r/"break-identity").exists():\n (r/"agent/installation.json").rename(r/"agent/installation.saved")\nif (r/"fail").exists(): sys.exit(1)\n')
        dropin = pathlib.Path(str(definition) + '.d')
        dropin.mkdir()
        (dropin/'audit.conf').write_text(f'[Service]\nExecStartPre=/usr/bin/python3 {probe}\n')
        systemctl('daemon-reload')
        for action in ('s', 't'):
            marker.unlink(missing_ok=True)
            t = tui()
            check(f'{action}: installed/stopped starts TUI-owned temporary agent', locked() and state()['ActiveState'] == 'inactive')
            t.action(action)
            t.expect('Action completed')
            wait(active, 'managed service active while TUI open')
            wait(locked, 'managed agent lock')
            check(f'{action}: lock released before native startup', marker.exists())
            pid = state()['MainPID']
            check(f'{action}: managed PID differs from live TUI', int(pid) != t.proc.pid and t.proc.poll() is None)
            # Longer than RestartSec=5 to detect an accidental lock-contention retry.
            end = time.monotonic() + 6
            while time.monotonic() < end:
                t.read()
                assert active() and state()['MainPID'] == pid and state()['NRestarts'] == '0'
                time.sleep(.1)
            check(f'{action}: active without auto-restart or lock contention')
            t.quit()
            check(f'{action}: managed service survives TUI exit', active() and state()['MainPID'] == pid and locked())
            cli('service', 'stop')
        for action in ('s', 't'):
            failure.touch()
            t = tui()
            t.action(action)
            t.expect('systemctl failed:')
            wait(locked, 'temporary restored after native failure')
            check(f'{action}: original managed error shown and temporary restored', state()['ActiveState'] == 'inactive')
            t.quit()
            wait(lambda: not locked(), 'recovered temporary stops on exit')
            failure.unlink()
        failure.touch()
        break_identity.touch()
        t = tui()
        t.action('s')
        t.expect('Temporary agent recovery also failed:')
        t.expect('systemctl failed:')
        check('both native failure and temporary restoration failure reported', not locked() and state()['ActiveState'] == 'inactive')
        (data/'installation.saved').rename(data/'installation.json')
        failure.unlink()
        break_identity.unlink()
        t.quit()
        cli('service', 'start')
        wait(active, 'managed attach setup')
        wait(locked, 'pre-existing managed agent owns directory')
        for key in ('q', '\x03'):
            pid = state()['MainPID']
            t = tui(temporary=False)
            t.quit(key)
            check('pre-existing managed service survives attached TUI exit', active() and state()['MainPID'] == pid)
        cli('service', 'stop')
        # Uninstall must leave an owned temporary agent alone.
        t = tui()
        t.action('u')
        t.expect('Action completed')
        check('uninstall preserves temporary ownership', locked() and not definition.exists())
        t.action('t')
        t.expect('Action completed')
        check('no-service Restart preserves temporary operation', locked())
        t.action('x')
        t.expect('Action completed')
        wait(lambda: not locked(), 'temporary stop')
        t.action('s')
        t.expect('Action completed')
        check('no-service Start starts temporary operation', locked())
        t.quit()
        wait(lambda: not locked(), 'no-service owned agent exit')
        # Existing install handoff must also release the lock first.
        marker.unlink(missing_ok=True)
        (root/'slow').touch()
        t = tui()
        t.action('i')
        t.click('[ Restart (T) ]')
        check('busy mutation ignores another action click', 'Type yes' not in t.read())
        t.click('[ Quit (Q) ]')
        t.expect('Finishing the current action')
        check('mouse Quit waits for mutation completion', t.proc.poll() is None)
        t.quit('q')
        (root/'slow').unlink()
        wait(active, 'TUI install starts service')
        check('Install still releases temporary lock before managed startup', marker.exists())
        check('TUI-installed managed service survives exit', active())
        cli('service', 'uninstall')
        definition.mkdir()
        t = tui()
        t.action('i')
        t.expect('Is a directory')
        check('Install failure restores owned temporary agent', locked())
        t.quit()
        wait(lambda: not locked(), 'install recovery stops on exit')
        definition.rmdir()
        external = subprocess.Popen([str(BIN), '--data-dir', str(data), 'daemon'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait(locked, 'external daemon')
        t = tui(temporary=False)
        t.quit()
        check('pre-existing external daemon survives TUI exit', external.poll() is None and locked())
        external.terminate()
        external.wait(timeout=15)
        external = None
    finally:
        for t in terminals:
            if t.master is not None:
                t.close()
        if external and external.poll() is None:
            external.terminate()
            external.wait(timeout=15)
        if unit:
            systemctl('disable', '--now', unit, ok=False)
        if definition:
            if definition.is_dir():
                definition.rmdir()
            else:
                definition.unlink(missing_ok=True)
        if dropin:
            shutil.rmtree(dropin, ignore_errors=True)
        if unit:
            systemctl('daemon-reload')
            systemctl('reset-failed', unit, ok=False)
        if gateway:
            gateway.terminate()
            gateway.wait(timeout=15)
    check('disposable service and drop-in removed', not definition.exists() and not dropin.exists())
check('disposable data removed', not root.exists())
print(f'{len(checks)} checks passed')
