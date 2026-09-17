#!/usr/bin/env python3
"""Linux TUI ownership regression against a disposable systemd user service.

Requires pyte, a running user service manager, and repository-built wayfinder and
wayfinder-gateway binaries. Installs only a uniquely named disposable service.
Recovery material is kept in memory; all service/data resources are cleaned up.
Run: python3 tests/tui_service.py
"""
import pyte
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
    def action(self, key):
        self.read()
        self.output = b''
        self.send(key)
        self.expect('Type yes, then Enter to confirm')
        self.send('yes\r')
        wait(lambda: 'Type yes, then Enter to confirm' not in self.read(), 'confirmation submitted')
    def quit(self, key='q'):
        self.send(key)
        wait(lambda: (self.read(), self.proc.poll() is not None)[1], 'TUI exit')
        check('terminal attributes and screen/paste modes restored', self.proc.returncode == 0 and termios.tcgetattr(self.slave) == self.before and b'\x1b[?1049l' in self.output and b'\x1b[?2004l' in self.output)
        self.close()
    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(timeout=15)
        if self.master is not None:
            os.close(self.master)
            os.close(self.slave)
            self.master = None

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
        for _ in range(5):
            t.send('\x1b[B')
            time.sleep(.12)
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
        enrollment.send('yes\r')
        wait(lambda: (enrollment.read(), enrollment.proc.poll() is not None)[1], 'enrollment')
        check('disposable identity enrolled against loopback gateway', enrollment.proc.returncode == 0)
        enrollment.output = b''
        enrollment.close()
        cache = data / 'update-check.json'
        cache.write_text(json.dumps({'checked':int(time.time()), 'latest':None, 'error':'local lifecycle audit'}))
        cache.chmod(0o600)
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
        probe.write_text('import fcntl, pathlib, sys\nr=pathlib.Path(__file__).parent\nwith open(r/"agent/daemon.lock", "a") as f:\n fcntl.flock(f, fcntl.LOCK_EX|fcntl.LOCK_NB)\n (r/"lock-released").write_text("released")\nif (r/"break-identity").exists():\n (r/"agent/installation.json").rename(r/"agent/installation.saved")\nif (r/"fail").exists(): sys.exit(1)\n')
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
        t = tui()
        t.action('i')
        t.expect('Action completed')
        wait(active, 'TUI install starts service')
        check('Install still releases temporary lock before managed startup', marker.exists())
        t.quit()
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
