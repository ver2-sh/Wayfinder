#!/usr/bin/env python3
"""Disposable process-level validation. Requires cryptography, mnemonic, websockets.
Never prints recovery material, private keys or bearer credentials.
"""
import asyncio
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import json
import os
from pathlib import Path
import re
import pty
import select
import socket
import ssl
import concurrent.futures
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from mnemonic import Mnemonic
import websockets

sys.dont_write_bytecode = True

REPO = Path(__file__).resolve().parents[1]
BIN = Path(os.environ.get('WAYFINDER_TEST_BIN', REPO / 'target/debug'))
processes = []
checks = []
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None
opener = urllib.request.build_opener(NoRedirect)
def check(name, condition):
    assert condition, name
    checks.append(name)
    print('PASS', name, flush=True)
def wait(fn, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(.1)
    raise AssertionError('Timed out waiting for lifecycle transition')
def spawn(args):
    p = subprocess.Popen([str(x) for x in args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    processes.append(p)
    return p
def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]
def mcp_origin(origin):
    return os.environ.get('WAYFINDER_TEST_MCP', origin) if origin == os.environ.get('WAYFINDER_TEST_GATEWAY') else origin
def http(origin, path, data=None, token=None, form=False, headers=None):
    if not path.startswith('/device/') and not path.startswith('/agent'):
        origin = mcp_origin(origin)
    h = {'User-Agent':'Wayfinder-validation/1', **(headers or {})}
    body = None
    if data is not None:
        body = (urllib.parse.urlencode(data) if form else json.dumps(data)).encode()
        h['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
    if token:
        h['Authorization'] = 'Bearer ' + token
    h['Accept'] = 'application/json, text/event-stream'
    request = urllib.request.Request(origin + path, body, h)
    try:
        r = opener.open(request, timeout=330)
    except urllib.error.HTTPError as e:
        r = e
    with r:
        raw = r.read().decode()
        try:
            value = json.loads(raw)
        except ValueError:
            value = raw
        return r.status, r.headers, value

def compact(v):
    return json.dumps(v, separators=(',', ':'), ensure_ascii=False).encode()
def field(s):
    b = s.encode()
    return len(b).to_bytes(4, 'big') + b
def cert_bytes(c):
    return (b'wayfinder/membership/v1\0' + c['version'].to_bytes(4,'big') + field(c['chain_id']) + bytes.fromhex(c['root_public']) + field(c['device_id']) + bytes.fromhex(c['device_public']) + bytes([1 if c['role']=='admin' else 2]) + field(c['name']))
def proof(i, origin, nonce, op):
    return b'wayfinder/administration/v1\0' + field(origin) + field(nonce) + field(hashlib.sha256(cert_bytes(i['certificate'])).hexdigest()) + field(compact(op).decode())
def signed(i, origin, op, nonce=None):
    nonce = nonce or http(origin, '/device/challenge?chain_id='+i['certificate']['chain_id'], {})[2]['nonce']
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(i['private_key']))
    return dict(certificate=i['certificate'],nonce=nonce,operation=op,signature=key.sign(proof(i,origin,nonce,op)).hex())
def operation(i, origin, op):
    return http(origin, '/device/operation', signed(i,origin,op))
def approval_hash(a):
    # Approval schema order, rather than HTTP JSON object key order.
    ordered = {k:a[k] for k in ('id','client_id','client_name','redirect_uri','permissions','expires')}
    return hashlib.sha256(compact(ordered)).hexdigest()
def enroll(root, name, phrase, origin, admin=False):
    data = root/name
    command = [str(BIN/'wayfinder'), '--data-dir', str(data), 'chain','join','--name',name,'--gateway',origin,'--phrase-stdin']
    if admin:
        command.append('--admin')
    result = subprocess.run(command,input=phrase.encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    assert result.returncode==0, 'Enrollment failed (secret-bearing output suppressed)'
    assert phrase.encode() not in result.stdout + result.stderr
    i = json.loads((data/'installation.json').read_text())
    p = spawn([BIN/'wayfinder','--data-dir',data,'daemon'])
    wait(lambda: json.loads((data/'status.json').read_text())['online'])
    return data,i,p

def start_auth(origin, client, scopes='read exec'):
    verifier=base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip('=')
    query=dict(response_type='code',client_id=client['client_id'],redirect_uri=client['redirect_uris'][0],scope=scopes,state='test-state',resource=mcp_origin(origin),code_challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('='),code_challenge_method='S256')
    status,headers,_=http(origin,'/oauth/authorize?'+urllib.parse.urlencode(query))
    assert status==303
    ticket=headers['Location']
    status,_,page=http(origin,ticket)
    assert status==200
    code=re.search(r'wayfinder authorize ([A-F0-9]+-[A-F0-9]+)',page)[1]
    return ticket,code,verifier

def finish_auth(origin, i, client, scopes='read exec'):
    ticket,code,verifier=start_auth(origin,client,scopes)
    assert http(origin,ticket)[0]==200
    status,_,a=operation(i,origin,dict(operation='pending',code=code))
    assert status==200
    approval=dict(operation='approve',code=code,request_hash=approval_hash(a))
    request=signed(i,origin,approval)
    assert http(origin,'/device/operation',request)[0]==200
    check('signed approval nonce is one-time',http(origin,'/device/operation',request)[0]==403)
    check('pairing request is one-time',operation(i,origin,approval)[0]==403)
    status,h,_=http(origin,ticket)
    assert status==303
    params=urllib.parse.parse_qs(urllib.parse.urlparse(h['Location']).query)
    check('OAuth state and issuer preserved',params['state']==['test-state'] and params['iss']==[mcp_origin(origin)])
    request=dict(grant_type='authorization_code',client_id=client['client_id'],code=params['code'][0],redirect_uri=client['redirect_uris'][0],resource=mcp_origin(origin),code_verifier=verifier)
    status,_,tokens=http(origin,'/oauth/token',request,form=True)
    assert status==200
    check('authorization code is one-time',http(origin,'/oauth/token',request,form=True)[0]==400)
    return tokens

def tool(origin, token, name, args=None):
    status,_,r=http(origin,'/',dict(jsonrpc='2.0',id=1,method='tools/call',params=dict(name=name,arguments=args or {})),token)
    if status!=200:
        return status,r
    assert 'result' in r, str(r)
    return status,r['result']
def exec_input(target,command,timeout=30000):
    return dict(target=target,command=command,timeout=timeout,cwd=None,env=None)
async def rejected_session(origin,i,mode):
    async with websockets.connect(origin.replace('https://','wss://').replace('http://','ws://')+'/agent?chain_id='+i['certificate']['chain_id'],user_agent_header='Wayfinder-validation/1') as ws:
        c=json.loads(await ws.recv())
        certificate=dict(i['certificate'])
        if mode=='certificate':
            certificate['name']='tampered'
        if mode=='chain':
            certificate['chain_id']='wfc1_'+'0'*64
        key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(i['private_key']))
        nonce=c['nonce'] if mode!='replay' else '0'*64
        metadata=dict(platform='other',arch='x86_64')
        data=b'wayfinder/session/v2\0'+field(origin)+field(nonce)+field(hashlib.sha256(cert_bytes(certificate)).hexdigest())+field(metadata['platform'])+field(metadata['arch'])
        sig=key.sign(data).hex() if mode!='signature' else '0'*128
        await ws.send(json.dumps(dict(type='authenticate',certificate=certificate,metadata=metadata,signature=sig)))
        try:
            reply=await asyncio.wait_for(ws.recv(),3)
            return json.loads(reply).get('type')!='ready'
        except websockets.exceptions.ConnectionClosed:
            return True

def recv_all(s, n):
    out = b''
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise ConnectionError('unexpected EOF')
        out += chunk
    return out
def app_session(sock):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(45)
    s.connect(str(sock))
    return s
def app_call(s, request):
    payload = compact(request)
    s.sendall(len(payload).to_bytes(4, 'big') + payload)
    n = int.from_bytes(recv_all(s, 4), 'big')
    return json.loads(recv_all(s, n))
def echo_service(prefaces):
    srv = socket.socket()
    srv.bind(('127.0.0.1', 0))
    srv.listen(4)
    def handle(c):
        with c:
            n = int.from_bytes(recv_all(c, 4), 'big')
            prefaces.append(json.loads(recv_all(c, n)))
            reply = compact(dict(version=1, ready=True))
            c.sendall(len(reply).to_bytes(4, 'big') + reply)
            while True:
                data = c.recv(65536)
                if not data:
                    return
                c.sendall(data)
    def accept():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()
    return srv
def interactive(args):
    master,slave=pty.openpty()
    process=subprocess.Popen([str(v) for v in args],stdin=slave,stdout=slave,stderr=slave)
    os.close(slave)
    captured=b''
    deadline=time.monotonic()+30
    answered=False
    try:
        while time.monotonic()<deadline:
            if select.select([master],[],[],.1)[0]:
                try:
                    part=os.read(master,65536)
                except OSError:
                    break
                if not part:
                    break
                captured+=part
                if not answered and b'Type yes:' in captured:
                    os.write(master,b'yes\n');answered=True
            if process.poll() is not None:
                break
        process.wait(timeout=10)
        assert process.returncode==0 and answered, 'Interactive CLI failed; captured output withheld'
        return captured.decode()
    finally:
        os.close(master)
        if process.poll() is None:
            process.kill();process.wait()

def run():
 with tempfile.TemporaryDirectory(prefix='wayfinder-validation-') as tmp:
    root=Path(tmp)
    # Each daemon owns a private runtime directory so the disposable endpoints
    # never collide with each other or a real installation on this host.
    def runtime(name):
        d = root/('rt-'+name)
        d.mkdir(mode=0o700, exist_ok=True)
        os.environ['XDG_RUNTIME_DIR'] = str(d)
        return d/'wayfinder/app.sock'
    external=os.environ.get('WAYFINDER_TEST_GATEWAY')
    origin=external or f'http://127.0.0.1:{port()}'
    gateway=None
    if not external:
        gateway=spawn([BIN/'wayfinder-gateway','--listen',origin.removeprefix('http://'),'--public-url',origin,'--data-dir',root/'gateway'])
    wait(lambda:http(origin,'/.well-known/oauth-authorization-server')[0]==200)
    status,h,_=http(origin,'/')
    check('unauthenticated MCP challenge',status==401 and 'resource_metadata=' in h['WWW-Authenticate'])
    if not external:
        check('host confusion rejected',http(origin,'/',headers={'Host':'attacker.invalid'})[0]==403)
    check('browser cannot invoke device API',http(origin,'/device/challenge',{},headers={'Origin':origin})[0]==403)
    # Only disposable creation: terminal output stays in memory, never test logs.
    created=root/'created'
    output=interactive([BIN/'wayfinder','--data-dir',created,'chain','create','--name','created','--gateway',origin])
    recovery=next(line.strip() for line in output.splitlines() if len(line.strip().split())==24 and Mnemonic('english').check(line.strip()))
    check('interactive creation saves device but not recovery',recovery not in (created/'installation.json').read_text())
    created_identity=json.loads((created/'installation.json').read_text())
    runtime('created')
    created_process=spawn([BIN/'wayfinder','--data-dir',created,'daemon'])
    wait(lambda:json.loads((created/'status.json').read_text())['online'])
    operation(created_identity,origin,dict(operation='revoke_device',device_id=created_identity['certificate']['device_id']))
    created_process.terminate();created_process.wait(timeout=10)
    del recovery,output,created_identity
    phrase=Mnemonic('english').generate(256)
    phrase_b=Mnemonic('english').generate(256)
    sock_a=runtime('a')
    a,ia,pa=enroll(root,'admin-a',phrase,origin,True)
    sock_b=runtime('b')
    b,ib,pb=enroll(root,'member-a',phrase,origin)
    runtime('c')
    c,ic,pc=enroll(root,'admin-b',phrase_b,origin,True)
    ca=ia['certificate'];cb=ib['certificate'];cc=ic['certificate']
    check('phrase deterministically reproduces Chain ID',ca['chain_id']==cb['chain_id']!=cc['chain_id'])
    entropy=Mnemonic('english').to_entropy(phrase)
    derived=HKDF(algorithm=hashes.SHA256(),length=32,salt=b'wayfinder/sync-chain/v1',info=b'root-signing/ed25519').derive(bytes(entropy))
    pub=Ed25519PrivateKey.from_private_bytes(derived).public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    check('independent HKDF and full SHA256 identity construction',ca['root_public']==pub.hex() and ca['chain_id']=='wfc1_'+hashlib.sha256(b'wayfinder/chain-id/v1\0'+pub).hexdigest())
    check('independent device keys',ia['private_key']!=ib['private_key'])
    check('private installation permissions',(a.stat().st_mode&0o777)==0o700 and ((a/'installation.json').stat().st_mode&0o777)==0o600)
    check('no persisted recovery or root seed',all(phrase not in p.read_text() and derived.hex() not in p.read_text() for p in a.glob('*.json')))
    for mode in ('certificate','chain','signature','replay'):
        check('reject invalid '+mode,asyncio.run(rejected_session(origin,ia,mode)))
    nodes=operation(ia,origin,dict(operation='devices'))[2]
    check('chain scoped device listing',len(nodes)==2 and all(n['online'] for n in nodes))
    check('member cannot administer',operation(ib,origin,dict(operation='grants'))[0]==403)
    status,_,client=http(origin,'/oauth/register',dict(client_name='Validation MCP',redirect_uris=['http://127.0.0.1:19876/callback'],token_endpoint_auth_method='none'))
    assert status==201
    check('unknown redirect rejected',http(origin,'/oauth/authorize?'+urllib.parse.urlencode(dict(client_id=client['client_id'],redirect_uri='https://attacker.invalid')))[0]==400)
    check('pending authorization cannot fabricate code',http(origin,'/oauth/token',dict(grant_type='authorization_code',client_id=client['client_id'],code='unapproved',redirect_uri=client['redirect_uris'][0],resource=mcp_origin(origin),code_verifier='x'*43),form=True)[0]==400)
    cli_ticket,cli_code,_=start_auth(origin,client)
    interactive([BIN/'wayfinder','--data-dir',a,'authorize',cli_code])
    check('CLI displays and explicitly approves OAuth request',http(origin,cli_ticket)[0]==303)
    tokens=finish_auth(origin,ia,client)
    token=tokens['access_token']
    status,nodes=tool(origin,token,'nodes')
    check('MCP nodes exact authorized chain',status==200 and {n['id'] for n in nodes['structuredContent']['nodes']}=={ca['device_id'],cb['device_id']})
    for target in (cc['device_id'],cc['name']):
        _,r=tool(origin,token,'exec',exec_input(target,'printf should-not-execute'))
        check('cross chain exec denied by '+('ID' if target==cc['device_id'] else 'name'),r['isError'] and not r['structuredContent']['stdout'])
    _,r=tool(origin,token,'exec',exec_input(cb['device_id'],'printf out; printf err >&2; exit 7'))
    result=r['structuredContent']
    check('stdout stderr exitCode',result['stdout']=='out' and result['stderr']=='err' and result['exitCode']==7)
    _,r=tool(origin,token,'exec',exec_input(cb['device_id'],'head -c 1048576 /dev/zero; head -c 1048576 /dev/zero >&2'))
    check('bounded control-byte output survives JSON frame expansion',len(r['structuredContent']['stdout'])==1048576 and len(r['structuredContent']['stderr'])==1048576 and not r['isError'])
    _,r=tool(origin,token,'exec',exec_input(cb['device_id'],'sleep 5',100))
    check('timeout and signal explicit',r['structuredContent']['timedOut'] and r['structuredContent']['signal'] is not None)
    _,r=tool(origin,token,'exec',exec_input(cb['device_id'],'kill -TERM $$'))
    check('shell signal explicit',r['structuredContent']['signal']=='SIG15')
    # HTTP disconnect must cancel the shell, including descendants.
    started=root/'cancel-started'; late=root/'cancel-late'
    command=f'printf started > {shlex.quote(str(started))}; sleep 4; printf failed > {shlex.quote(str(late))}'
    u=urllib.parse.urlparse(mcp_origin(origin))
    sock=socket.create_connection((u.hostname,u.port or 443))
    if u.scheme=='https':
        sock=ssl.create_default_context().wrap_socket(sock,server_hostname=u.hostname)
    payload=compact(dict(jsonrpc='2.0',id=7,method='tools/call',params=dict(name='exec',arguments=exec_input(cb['device_id'],command))))
    headers=(f'POST / HTTP/1.1\r\nHost: {u.netloc}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {len(payload)}\r\n\r\n').encode()
    sock.sendall(headers+payload);wait(started.exists);sock.close();time.sleep(5)
    check('HTTP disconnect cancels remote process group',not late.exists())
    with concurrent.futures.ThreadPoolExecutor() as pool:
        marker=root/'dispatch-count'
        call=pool.submit(tool,origin,token,'exec',exec_input(cb['device_id'],f'printf once >> {shlex.quote(str(marker))}; sleep 30'))
        wait(marker.exists)
        pb.terminate();pb.wait(timeout=10)
        response=call.result(timeout=30)[1]
        check('uncertain dispatch reports error and is never retried',response['isError'] and marker.read_text()=='once')
    wait(lambda:not next(n for n in operation(ia,origin,dict(operation='devices'))[2] if n['id']==cb['device_id'])['online'])
    check('offline node unreachable',tool(origin,token,'exec',exec_input(cb['device_id'],'true'))[1]['isError'])
    runtime('b')
    pb=spawn([BIN/'wayfinder','--data-dir',b,'daemon'])
    wait(lambda:next(n for n in operation(ia,origin,dict(operation='devices'))[2] if n['id']==cb['device_id'])['online'])
    check('restart preserves identity',json.loads((b/'installation.json').read_text())==ib)
    if not external:
        # Generic local application transport: endpoints appear automatically
        # under each daemon's runtime directory; unconfigured applications
        # register session-owned services and open exact-device streams.
        bare=lambda d:d['device_id'].removeprefix('wfd1_')
        wait(lambda:sock_a.exists() and sock_b.exists())
        app_a=app_session(sock_a)
        # The roster cache refreshes periodically over the gateway session.
        wait(lambda:{n['id'] for n in app_call(app_a,dict(op='status')).get('value',{}).get('nodes',[])}=={bare(ca),bare(cb)})
        status=app_call(app_a,dict(op='status'))
        check('local status is a sanitized chain view','value' in status and {n['id'] for n in status['value']['nodes']}=={bare(ca),bare(cb)} and all(set(n)=={'id','name','local','reachable'} for n in status['value']['nodes']))
        check('status has no credentials or private state',all(v not in json.dumps(status) for v in (phrase,ia['private_key'])))
        prefaces=[]
        backend=echo_service(prefaces)
        credential=os.urandom(32).hex()
        app_b=app_session(sock_b)
        reply=app_call(app_b,dict(op='register_service',service='echo.v1',address=f'127.0.0.1:{backend.getsockname()[1]}',credential=credential))
        check('loopback service registration admitted',reply.get('value',{}).get('registered'))
        check('non-loopback backend refused','error' in app_call(app_b,dict(op='register_service',service='net.v1',address='8.8.8.8:53',credential=credential)))
        check('invalid service name refused','error' in app_call(app_b,dict(op='register_service',service='Invalid Name',address='127.0.0.1:9',credential=credential)))
        thief=app_session(sock_b)
        check('registration cannot be taken by another session','error' in app_call(thief,dict(op='register_service',service='echo.v1',address=f'127.0.0.1:{backend.getsockname()[1]}',credential=credential)))
        opening=app_session(sock_a)
        reply=app_call(opening,dict(op='open_service',target=bare(cb),service='echo.v1'))
        check('exact remote device service opens',reply==dict(version=1,ready=True))
        opening.sendall(b'secret application bytes')
        check('end-to-end stream echoes through relay',recv_all(opening,24)==b'secret application bytes')
        opening.shutdown(socket.SHUT_WR)
        check('half-close propagates EOF through relay',opening.recv(1)==b'')
        opening.close()
        check('preface binds credential source target and service',prefaces and prefaces[0]['credential']==credential and prefaces[0]['source']==bare(ca) and prefaces[0]['target']==bare(cb) and prefaces[0]['service']=='echo.v1')
        denied=app_session(sock_a)
        check('unregistered service rejected','not registered' in app_call(denied,dict(op='open_service',target=bare(cb),service='absent.v1')).get('error',''))
        denied.close()
        loop=app_session(sock_a)
        check('local device is not a service target','error' in app_call(loop,dict(op='open_service',target=bare(ca),service='echo.v1')))
        loop.close()
        foreign=app_session(sock_a)
        check('cross-chain service target refused','error' in app_call(foreign,dict(op='open_service',target=bare(cc),service='echo.v1')))
        foreign.close()
        app_b.close();thief.close()
        def unregistered():
            s=app_session(sock_a)
            r=app_call(s,dict(op='open_service',target=bare(cb),service='echo.v1'))
            s.close()
            return 'not registered' in r.get('error','')
        wait(unregistered)
        check('registration dies with the application session',True)
        backend.close()
    readonly=finish_auth(origin,ia,client,'read')
    check('read token cannot exec',tool(origin,readonly['access_token'],'exec',exec_input(ca['device_id'],'true'))[1]['isError'])
    grants=operation(ia,origin,dict(operation='grants'))[2]
    check('scopes and chain stored on grants',len(grants)==2 and all(g['chain_id']==ca['chain_id'] for g in grants))
    grant=next(g for g in grants if 'exec' in g['permissions'])
    check('cross chain grant revoke denied',operation(ic,origin,dict(operation='revoke_grant',grant_id=grant['id']))[0]==403)
    assert operation(ia,origin,dict(operation='revoke_grant',grant_id=grant['id']))[0]==200
    check('revoked grant immediately denied',tool(origin,token,'nodes')[0]==401)
    assert operation(ia,origin,dict(operation='revoke_device',device_id=cb['device_id']))[0]==200
    check('revoked device cannot reconnect',asyncio.run(rejected_session(origin,ib,'revoked')))
    check('cross chain device revoke denied',operation(ia,origin,dict(operation='revoke_device',device_id=cc['device_id']))[0]==403)
    refresh=dict(grant_type='refresh_token',client_id=client['client_id'],resource=mcp_origin(origin),refresh_token=readonly['refresh_token'])
    status,_,rotated=http(origin,'/oauth/token',refresh,form=True)
    check('refresh rotates tokens',status==200 and rotated['refresh_token']!=readonly['refresh_token'])
    check('old access invalid after refresh',tool(origin,readonly['access_token'],'nodes')[0]==401)
    check('refresh reuse revokes grant',http(origin,'/oauth/token',refresh,form=True)[0]==400 and tool(origin,rotated['access_token'],'nodes')[0]==401)
    if gateway:
        gateway.terminate();gateway.wait(timeout=10)
        gateway=spawn([BIN/'wayfinder-gateway','--listen',origin.removeprefix('http://'),'--public-url',origin,'--data-dir',root/'gateway'])
        wait(lambda:operation(ia,origin,dict(operation='devices'))[0]==200,65)
        check('gateway restart reconnect and durable revocation',asyncio.run(rejected_session(origin,ib,'revoked')))
        db=(root/'gateway/gateway.sqlite').read_bytes()
        check('gateway never stores recovery private keys or raw tokens',all(v.encode() not in db for v in (phrase,derived.hex(),ia['private_key'],ib['private_key'],token,readonly['refresh_token'])))
    other=f'http://127.0.0.1:{port()}'
    spawn([BIN/'wayfinder-gateway','--listen',other.removeprefix('http://'),'--public-url',other,'--data-dir',root/'other-gateway'])
    wait(lambda:http(other,'/.well-known/oauth-authorization-server')[0]==200)
    check('old revoked certificate cannot bootstrap fresh target', http(other, '/device/operation', signed(ib, other, dict(operation='devices')))[0] == 403 and asyncio.run(rejected_session(other,ib,'revoked')))
    def migrate(data, target, secret=phrase):
        result = subprocess.run([str(BIN/'wayfinder'), '--data-dir', str(data), 'gateway', 'migrate', target, '--phrase-stdin'], input=secret.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert secret.encode() not in result.stdout + result.stderr
        return result.returncode
    before=(a/'installation.json').read_bytes()
    check('migration refuses independently owned agent', migrate(a, other) != 0 and (a/'installation.json').read_bytes()==before)
    pa.terminate();pa.wait(timeout=10)
    check('wrong recovery root leaves old installation intact', migrate(a, other, phrase_b) != 0 and (a/'installation.json').read_bytes()==before)
    check('unreachable target leaves old installation intact', migrate(a, f'http://127.0.0.1:{port()}') != 0 and (a/'installation.json').read_bytes()==before)
    class RejectRegistration(BaseHTTPRequestHandler):
        admitted = False
        def log_message(self, *args): pass
        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get('Content-Length', 0)))
            assert phrase.encode() not in raw
            if self.path.startswith('/device/challenge'):
                result = dict(version=1, gateway=failed_origin, nonce='disposable-target-challenge')
            else:
                RejectRegistration.admitted = True
                result = dict(admitted=True)
            encoded = json.dumps(result).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers();self.wfile.write(encoded)
        def do_GET(self): self.send_error(403)
    with ThreadingHTTPServer(('127.0.0.1', 0), RejectRegistration) as server:
        failed_origin=f'http://127.0.0.1:{server.server_port}'
        thread=threading.Thread(target=server.serve_forever, daemon=True);thread.start()
        try:
            check('registration failure after target admission preserves old installation', migrate(a,failed_origin)!=0 and RejectRegistration.admitted and (a/'installation.json').read_bytes()==before)
        finally:
            server.shutdown();thread.join()
    check('explicit root-authorized migration succeeds', migrate(a, other)==0)
    moved=json.loads((a/'installation.json').read_text())
    check('migration preserves Chain ID Device ID certificate role and private key', moved == {**ia, 'gateway':other})
    runtime('a')
    pa=spawn([BIN/'wayfinder','--data-dir',a,'daemon'])
    wait(lambda:operation(moved,other,dict(operation='devices'))[0]==200)
    check('same device connects at target', any(n['id']==ca['device_id'] and n['online'] for n in operation(moved,other,dict(operation='devices'))[2]))
    pb.terminate();pb.wait(timeout=10)
    check('root authorizes formerly revoked device at fresh destination', migrate(b,other)==0)
    assert operation(moved,other,dict(operation='revoke_device',device_id=cb['device_id']))[0]==200
    before_b=(b/'installation.json').read_bytes()
    check('target tombstone rejects even recovery-root migration', migrate(b,origin)!=0 and (b/'installation.json').read_bytes()==before_b)
    pa.terminate();pa.wait(timeout=10)
    check('same installation migrates back to original gateway', migrate(a,origin)==0 and json.loads((a/'installation.json').read_text())==ia)
    runtime('a')
    pa=spawn([BIN/'wayfinder','--data-dir',a,'daemon'])
    wait(lambda:operation(ia,origin,dict(operation='devices'))[0]==200)
    # Hosted validation leaves only explicitly revoked public disposable records.
    if external:
        operation(ic,origin,dict(operation='revoke_device',device_id=cc['device_id']))
        operation(ia,origin,dict(operation='revoke_device',device_id=ca['device_id']))
    print(f'{len(checks)} checks passed; no secrets printed',flush=True)

if __name__=='__main__':
    try:
        run()
    finally:
        for p in processes:
            if p.poll() is None:
                p.terminate()
        for p in processes:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill();p.wait()
