#!/usr/bin/env python3
"""Real processes and encrypted peers; build wayfinder before running this test."""
import array
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("echo", REPO / "examples/echo_app.py")
echo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(echo)
BINARY = REPO / "target/debug/wayfinder"
processes = []
checks = []
SEPARATE = os.geteuid() == 0
DAEMON_UID, APP_UID, APP_GID, DENIED_UID = 61001, 61002, 61003, 61004

def identity(application=False):
    if not SEPARATE:
        return {}
    return dict(user=APP_UID if application else DAEMON_UID,
                group=APP_UID if application else DAEMON_UID,
                extra_groups=[APP_GID])


def check(name, value):
    assert value, name
    checks.append(name)
    print("PASS", name, flush=True)

def wait(fn):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            result = fn()
            if result:
                return result
        except (OSError, ValueError, EOFError):
            pass
        time.sleep(.1)
    raise AssertionError("Timed out waiting for lifecycle transition")

def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def spawn(args, env):
    p = subprocess.Popen(args, env=env, **identity(args[0] == sys.executable), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(p)
    return p

def control(node, op, token=None):
    descriptor = json.loads((node["data"] / "control.json").read_text())
    req = urllib.request.Request("http://" + descriptor["address"] + "/control", json.dumps(op).encode(),
                                 {"Content-Type": "application/json", "Authorization": "Bearer " + (token or descriptor["credential"])})
    with urllib.request.urlopen(req, timeout=5) as r:
        reply = json.load(r)
    if reply.get("error"):
        raise ValueError(reply["error"])
    return reply["value"]

def connect(node):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(5)
    path = str(node["run"] / "wayfinder/app.sock")
    if SEPARATE:
        # Establish the connection as the application UID, then transfer its fd
        # to the test driver. SO_PEERCRED remains the application identity.
        parent, child = socket.socketpair()
        code = """import socket,sys,array
c=socket.socket(fileno=int(sys.argv[1]));s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[2])
c.sendmsg([b'x'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[s.fileno()]))])
"""
        p = subprocess.Popen([sys.executable, "-c", code, str(child.fileno()), path],
                             pass_fds=[child.fileno()], **identity(True))
        child.close()
        _, ancillary, _, _ = parent.recvmsg(1, socket.CMSG_SPACE(4))
        p.wait(timeout=5)
        parent.close()
        assert p.returncode == 0 and ancillary
        fd = array.array('i'); fd.frombytes(ancillary[0][2])
        s.close(); s = socket.socket(fileno=fd[0]); s.settimeout(5)
    else:
        s.connect(path)
    return s

def active(node):
    return control(node, {"op": "applications"})["active"]

def open_service(source, target, name=echo.SERVICE):
    s = connect(source)
    echo.send(s, {"op": "open_service", "target": target["id"], "service": name})
    return s, echo.receive(s)

def start_daemon(node):
    node["process"] = spawn([str(BINARY), "--data-dir", str(node["data"]), "daemon"], node["env"])
    wait(lambda: control(node, {"op": "status"}))

try:
    with tempfile.TemporaryDirectory(prefix="wayfinder-apps-") as tmp:
        Path(tmp).chmod(0o755)
        nodes = []
        for name in ("a", "b", "c"):
            root = Path(tmp) / name
            root.mkdir()
            node = {"data": root / "private", "run": root / "run", "mcp": port()}
            node["run"].mkdir(mode=0o700)
            if SEPARATE:
                os.chown(root, DAEMON_UID, DAEMON_UID)
                os.chown(node["run"], DAEMON_UID, DAEMON_UID)
                node["run"].chmod(0o755)
                app_dir = node["run"] / "wayfinder"
                app_dir.mkdir()
                os.chown(app_dir, DAEMON_UID, APP_GID)
                app_dir.chmod(0o2750)
            node["env"] = dict(os.environ, XDG_RUNTIME_DIR=str(node["run"]))
            subprocess.run([str(BINARY), "--data-dir", str(node["data"]), "init", "--name", name,
                            "--mcp-listen", f'127.0.0.1:{node["mcp"]}', "--peer-listen", f"127.0.0.1:{port()}"], check=True, capture_output=True, **identity())
            start_daemon(node)
            node["id"] = control(node, {"op": "status"})["node"]["id"]
            nodes.append(node)
        a, b, c = nodes
        control(a, {"op": "create", "name": "generic applications"})
        for node in (b, c):
            invitation = control(a, {"op": "invite"})["invitation"]
            control(node, {"op": "join", "invitation": invitation})
        wait(lambda: all(len(control(n, {"op": "status"})["nodes"]) == 3 for n in nodes))
        for node in (a, b):
            node["app"] = spawn([sys.executable, str(REPO / "examples/echo_app.py")], node["env"])
            wait(lambda: echo.SERVICE in active(node))
            check("no application configuration persisted", not (node["data"] / "services.json").exists())
            check("socket permissions", (node["run"] / "wayfinder/app.sock").stat().st_mode & 0o777 == (0o660 if SEPARATE else 0o600))
        for source, target in ((a, b), (b, a)):
            s, reply = open_service(source, target)
            with s:
                check("encrypted exact-node admission", reply == {"version": 1, "ready": True})
                payload = os.urandom(200000)
                # Bound chunks to exercise backpressure without deadlocking echo.
                for i in range(0, len(payload), 8192):
                    chunk = payload[i:i+8192]
                    s.sendall(chunk)
                    assert echo.read_exact(s, len(chunk)) == chunk
                check("bidirectional echo bytes", True)
        s, reply = open_service(a, c)
        s.close()
        check("ordinary member has no service", "error" in reply)
        for op in ({"op": "create", "name": "forbidden"}, {"op": "exec", "command": "true"}, {"op": "details", "id": a["id"]}, {"op":"join","invitation":"x"}, {"op":"invite"}, {"op":"remove","id":a["id"]}, {"op":"mcp"}):
            with connect(a) as s:
                echo.send(s, op)
                check("application decoder excludes administration", s.recv(1) == b"")
        with connect(a) as s:
            echo.send(s, {"op": "status"})
            value = echo.receive(s)["value"]
            check("public status only", set(value) == {"nodes", "conflict"} and all(set(n) == {"id", "name", "local", "reachable"} for n in value["nodes"]))
        for service, address, credential in (("Invalid/Name", "127.0.0.1:12345", "a" * 64),
                                             ("valid.v1", "192.0.2.1:12345", "a" * 64),
                                             ("valid.v1", "127.0.0.1:12345", "short")):
            with connect(a) as s:
                echo.send(s, {"op":"register_service", "service":service, "address":address, "credential":credential})
                check("invalid registration rejected", "error" in echo.receive(s))
        with connect(a) as s:
            echo.send(s, {"op":"open_service", "service":echo.SERVICE, "target":"0" * 64})
            check("unknown exact target rejected", "error" in echo.receive(s))
        if SEPARATE:
            app_socket = a["run"] / "wayfinder/app.sock"
            code = """import socket,sys
s=socket.socket(socket.AF_UNIX)
try:s.connect(sys.argv[1])
except PermissionError:sys.exit(0)
sys.exit(1)
"""
            denied = subprocess.run([sys.executable, "-c", code, str(app_socket)],
                                    user=DENIED_UID, group=DENIED_UID, extra_groups=[])
            check("unauthorized UID denied by kernel", denied.returncode == 0)
            for node in (a,b):
                check("private directory owner-only", node["data"].stat().st_mode & 0o777 == 0o700)
                for name in ("identity.json", "config.json", "state.json", "control.json"):
                    file = node["data"] / name
                    check(name + " owner-only", file.stat().st_mode & 0o777 == 0o600)
                    code = """import sys
try:open(sys.argv[1]).read()
except PermissionError:sys.exit(0)
sys.exit(1)
"""
                    denied = subprocess.run([sys.executable, "-c", code, str(file)], **identity(True))
                    check("application UID cannot read " + name, denied.returncode == 0)
        with connect(a) as s:
            echo.send(s, {"op": "register_service", "service": echo.SERVICE, "address": "127.0.0.1:12345", "credential": "a" * 64})
            check("another session cannot take over", "error" in echo.receive(s))
            echo.send(s, {"op": "unregister_service", "service": echo.SERVICE})
            check("another session cannot unregister", "error" in echo.receive(s))
        security_session = connect(a)
        echo.send(security_session, {"op":"register_service", "service":"authorization.test.v1", "address":"127.0.0.1:12345", "credential":"a" * 64})
        check("credential belongs to a live registration", "value" in echo.receive(security_session))
        try:
            control(a, {"op": "status"}, "a" * 64)
            raise AssertionError("Admin accepted application credential")
        except urllib.error.HTTPError as e:
            check("application credential rejected by admin", e.code == 401)
        req = urllib.request.Request(f'http://127.0.0.1:{a["mcp"]}/mcp', b'{}', {"Content-Type": "application/json", "Authorization": "Bearer " + "a" * 64})
        try:
            urllib.request.urlopen(req)
            raise AssertionError("MCP accepted application credential")
        except urllib.error.HTTPError as e:
            check("application credential rejected by MCP", e.code == 401)
        security_session.close()
        b["app"].kill(); b["app"].wait()
        wait(lambda: echo.SERVICE not in active(b))
        s, reply = open_service(a, b); s.close()
        check("killed application registration disappears", "error" in reply)
        b["app"] = spawn([sys.executable, str(REPO / "examples/echo_app.py")], b["env"])
        wait(lambda: echo.SERVICE in active(b))
        check("application restart registers without daemon restart", b["process"].poll() is None)
        b["process"].kill(); b["process"].wait()
        start_daemon(b)
        wait(lambda: echo.SERVICE in active(b))
        s, reply = open_service(a, b)
        with s:
            check("daemon crash restart restores application automatically", reply.get("ready"))
            s.sendall(b"reconnected")
            check("service works after reconnect", echo.read_exact(s, 11) == b"reconnected")
        with connect(a) as s:
            echo.send(s, {"op": "register_service", "service": "database.cluster.v1", "address": "127.0.0.1:12345", "credential": "b" * 64})
            check("unrelated name supported", "value" in echo.receive(s))
            echo.send(s, {"op": "unregister_service", "service": "database.cluster.v1"})
            check("explicit unregister", "value" in echo.receive(s) and "database.cluster.v1" not in active(a))
        # Stop while the temporary directory still exists.
        for p in processes:
            if p.poll() is None: p.terminate()
        for p in processes:
            p.wait(timeout=10)
    print(json.dumps({"passed": len(checks), "checks": checks}))
finally:
    for p in processes:
        if p.poll() is None: p.kill()
    for p in processes: p.wait()
