#!/usr/bin/env python3
# backend/server.py — hardened local assessment control plane
import json, hashlib, os, socket, ipaddress, secrets, ssl, urllib.parse, http.client, hmac
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HOST='127.0.0.1'; PORT=8000
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE=os.path.join(ROOT,'backend/security_state.json')
AUDIT=os.path.join(ROOT,'backend/sentinelscan_audit.jsonl')
HISTORY=os.path.join(ROOT,'backend/scan_history.json')
TOKEN_FILE=os.path.join(ROOT,'backend/.session_token')
ANCHOR=os.path.join(ROOT,'evidence/audit_anchor.json')
ANCHOR_KEY=os.path.join(ROOT,'backend/.audit_anchor_secret')

CONTROL_META={
 'AUTH-001':('Authentication enforcement','Authentication & Session Management','A07: Identification and Authentication Failures'),
 'AUTHZ-001':('API authorization enforcement','Authorization & Access Control','A01: Broken Access Control'),
 'INPUT-001':('Input validation','Input Validation & Data Handling','A03: Injection'),
 'API-001':('HTTP method enforcement','API Security','API8: Security Misconfiguration'),
 'CLIENT-001':('Client-side credential exposure','Client-Side Security','A05: Security Misconfiguration'),
 'CORS-001':('CORS origin enforcement','Secure Communication','A05: Security Misconfiguration'),
 'DATA-001':('Debug endpoint exposure','Data Storage & Privacy','A05: Security Misconfiguration')
}
ALLOWED_ORIGINS={'http://127.0.0.1:8000','http://localhost:8000'}

def now(): return datetime.now(timezone.utc).isoformat()
def sha(data): return hashlib.sha256(data.encode()).hexdigest()

def load_or_create_secret(path):
    if os.path.exists(path):
        with open(path,'r',encoding='utf-8') as f:return f.read().strip()
    value=secrets.token_urlsafe(32); os.makedirs(os.path.dirname(path),exist_ok=True)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as f:f.write(value)
    return value

SESSION_TOKEN=load_or_create_secret(TOKEN_FILE)
ANCHOR_SECRET=load_or_create_secret(ANCHOR_KEY)

def token_ok(handler):
    h=handler.headers.get('Authorization','')
    return h.startswith('Bearer ') and secrets.compare_digest(h[7:],SESSION_TOKEN)

def origin_ok(handler):
    origin=handler.headers.get('Origin')
    return origin is None or origin in ALLOWED_ORIGINS

def load_json(path, default):
    try:
        with open(path,encoding='utf-8') as f:return json.load(f)
    except Exception:return default

def save_json(path,value):
    os.makedirs(os.path.dirname(path),exist_ok=True)
    tmp=path+'.tmp'
    with open(tmp,'w',encoding='utf-8') as f:json.dump(value,f,indent=2)
    os.chmod(tmp,0o600); os.replace(tmp,path)

def load_state(): return load_json(STATE,{'findings':{},'last_run':None,'last_results':[]})

def _last_chain_hash():
    if not os.path.exists(AUDIT): return '0'*64
    last='0'*64
    with open(AUDIT,'r',encoding='utf-8') as f:
        for line in f:
            if line.strip():
                try:last=json.loads(line).get('hash',last)
                except Exception:pass
    return last

def _audit_bytes():
    if not os.path.exists(AUDIT): return b''
    with open(AUDIT,'rb') as f:return f.read()

def _anchor_manifest():
    verify=verify_chain()
    data=_audit_bytes()
    return {
        'format':'SentinelScan audit anchor v1',
        'anchored_at':now(),
        'audit_file':'backend/sentinelscan_audit.jsonl',
        'audit_sha256':hashlib.sha256(data).hexdigest(),
        'records':verify['records'],
        'first_hash':verify.get('first_hash'),
        'last_hash':verify.get('last_hash','0'*64),
        'chain_ok':verify['ok']
    }

def write_audit_anchor():
    manifest=_anchor_manifest()
    canonical=json.dumps(manifest,sort_keys=True,separators=(',',':'))
    signature=hmac.new(ANCHOR_SECRET.encode(),canonical.encode(),hashlib.sha256).hexdigest()
    save_json(ANCHOR,{'manifest':manifest,'signature':signature,'signature_alg':'HMAC-SHA256'})

def verify_audit_anchor():
    anchor=load_json(ANCHOR,None)
    if not anchor:return {'ok':False,'reason':'anchor missing'}
    manifest=anchor.get('manifest'); sig=anchor.get('signature','')
    if not isinstance(manifest,dict):return {'ok':False,'reason':'invalid manifest'}
    canonical=json.dumps(manifest,sort_keys=True,separators=(',',':'))
    expected=hmac.new(ANCHOR_SECRET.encode(),canonical.encode(),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig,expected):return {'ok':False,'reason':'signature mismatch'}
    current=_anchor_manifest()
    if current['audit_sha256']!=manifest.get('audit_sha256') or current['last_hash']!=manifest.get('last_hash') or current['records']!=manifest.get('records'):
        return {'ok':False,'reason':'audit differs from anchored manifest','anchored':manifest,'current':current}
    return {'ok':True,'manifest':manifest}

def audit(obj):
    os.makedirs(os.path.dirname(AUDIT),exist_ok=True)
    prev=_last_chain_hash(); payload=json.dumps(obj,sort_keys=True,separators=(',',':')); h=sha(prev+payload)
    record=json.dumps({'prev_hash':prev,'hash':h,'payload':obj},sort_keys=True)
    fd=os.open(AUDIT,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    try:os.write(fd,(record+'\n').encode());os.fsync(fd)
    finally:os.close(fd)
    write_audit_anchor()
    return h

def verify_chain():
    if not os.path.exists(AUDIT):return {'ok':True,'records':0,'broken_at':None,'first_hash':None,'last_hash':'0'*64}
    prev='0'*64;n=0;first=None
    with open(AUDIT,'r',encoding='utf-8') as f:
        for i,line in enumerate(f,1):
            if not line.strip():continue
            n+=1
            try:rec=json.loads(line)
            except Exception:return {'ok':False,'records':n,'broken_at':i,'reason':'bad json','first_hash':first,'last_hash':prev}
            if rec.get('prev_hash')!=prev:return {'ok':False,'records':n,'broken_at':i,'reason':'prev_hash mismatch','first_hash':first,'last_hash':prev}
            payload=json.dumps(rec['payload'],sort_keys=True,separators=(',',':'))
            if sha(prev+payload)!=rec.get('hash'):return {'ok':False,'records':n,'broken_at':i,'reason':'hash mismatch','first_hash':first,'last_hash':prev}
            prev=rec['hash']; first=first or prev
    return {'ok':True,'records':n,'broken_at':None,'first_hash':first,'last_hash':prev}

if not os.path.exists(ANCHOR):
    # Create a signed empty-chain anchor on first startup.
    write_audit_anchor()

def resolve_loopback(url):
    p=urllib.parse.urlparse(url)
    if p.scheme not in ('http','https'):return None,'scheme must be http/https'
    if p.username or p.password:return None,'userinfo not allowed'
    if not p.hostname:return None,'missing host'
    try:port=p.port or (443 if p.scheme=='https' else 80)
    except ValueError:return None,'invalid port'
    try:infos=socket.getaddrinfo(p.hostname,port,type=socket.SOCK_STREAM)
    except Exception:return None,'dns resolution failed'
    ips=[]
    for i in infos:
        try:ips.append(ipaddress.ip_address(i[4][0]))
        except ValueError:return None,'invalid ip'
    if not ips:return None,'no addresses'
    if not all(a.is_loopback for a in ips):return None,'target must resolve exclusively to loopback'
    return {'scheme':p.scheme,'host':p.hostname,'port':port,'path':p.path or '/','query':p.query,'ip':str(ips[0])},''

class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """TLS uses the original hostname for SNI + certificate verification while the socket connects to a pinned IP."""
    def __init__(self, hostname, ip, port=443, timeout=5, context=None):
        super().__init__(hostname,port=port,timeout=timeout,context=context)
        self.pinned_ip=ip
    def connect(self):
        self.sock=socket.create_connection((self.pinned_ip,self.port),self.timeout)
        context=getattr(self,'_context',None)
        if context is None:
            context=ssl.create_default_context()
            self._context=context
        self.sock=context.wrap_socket(self.sock,server_hostname=self.host)

def pinned_request(target,method='GET',headers=None,body=None):
    headers=dict(headers or {})
    headers.setdefault('Host',target['host'] if target['port'] in (80,443) else f"{target['host']}:{target['port']}")
    headers.setdefault('Connection','close')
    path=target['path']+(('?'+target['query']) if target['query'] else '')
    try:
        if target['scheme']=='https':
            ctx=ssl.create_default_context()
            conn=PinnedHTTPSConnection(target['host'],target['ip'],target['port'],timeout=5,context=ctx)
        else:
            conn=http.client.HTTPConnection(target['ip'],target['port'],timeout=5)
        conn.request(method,path,body=body,headers=headers)
        r=conn.getresponse();text=r.read(12000).decode('utf-8','replace')
        return {'status':r.status,'headers':dict(r.getheaders()),'body':text,'url':f"{target['scheme']}://{target['host']}:{target['port']}{path}",'redirect_blocked':False}
    except Exception as e:
        return {'status':0,'headers':{},'body':f'transport error: {e.__class__.__name__}','url':f"{target['scheme']}://{target['host']}:{target['port']}{path}",'transport_error':True}
    finally:
        try:conn.close()
        except Exception:pass

def make_finding(ev):
    meta=CONTROL_META.get(ev['id'],(ev['title'],'Security Assessment','Unmapped'))
    cvss={'score':5.3,'severity':'Medium','vector':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'} if ev['verdict']=='FAIL' else None
    return {'id':ev['id'],'title':ev['title'],'status':'Open','severity':'Medium' if cvss else 'Informational','cvss':cvss,'category':meta[1],'owasp':meta[2],'source':ev.get('source','World Monitor target'),'component':urllib.parse.urlparse(ev['target']).path or '/','description':ev['description'],'preconditions':'Authorized local/staging target only.','steps':[f"Send {ev['method']} request to {ev['target']}",f"Observe HTTP {ev['response']['status']}",f"Compare actual behavior with expected: {ev['expected']}"],'impact':'Potential confidentiality, integrity, or availability impact depends on the affected component and data exposed.','remediation':'Enforce the documented security control server-side and add a regression test for the affected route.','evidence':ev,'retest':None,'regression':None,'created_at':ev['timestamp']}

def check(base):
    base=base.rstrip('/')
    checks=[
      ('AUTH-001',base+'/api/protected','GET',{},'Protected endpoint should reject unauthenticated access',lambda r:r['status'] in (401,403)),
      ('AUTHZ-001',base+'/api/admin','GET',{},'Admin API should reject missing authorization',lambda r:r['status'] in (401,403)),
      ('INPUT-001',base+'/api/rss-proxy','GET',{},'Missing required URL parameter should be rejected',lambda r:r['status'] in (400,422)),
      ('API-001',base+'/api/brief','POST',{'Content-Type':'application/json'},'GET-only operation should reject POST',lambda r:r['status'] in (405,404)),
      ('CLIENT-001',base+'/','GET',{},'HTML should not expose obvious secrets',lambda r:not r.get('transport_error') and not any(x in r['body'].lower() for x in ('api_key=','secret_key=','private_key='))),
      ('CORS-001',base+'/api/brief','GET',{'Origin':'https://evil.example'},'Disallowed origin should not be trusted',lambda r:r['headers'].get('Access-Control-Allow-Origin','') not in ('*','https://evil.example')),
      ('DATA-001',base+'/api/debug-env.js','GET',{},'Debug endpoint should not be publicly exposed',lambda r:r['status'] in (404,403)),]
    results=[]
    for cid,url,method,headers,expected,validator in checks:
        tgt,err=resolve_loopback(url);r={'status':0,'headers':{},'body':f'blocked: {err}','url':url,'transport_error':True} if tgt is None else pinned_request(tgt,method,headers)
        verdict='ERROR' if r.get('transport_error') else ('PASS' if validator(r) else 'FAIL')
        ev={'id':cid,'title':CONTROL_META[cid][0],'target':url,'method':method,'request_headers':headers,'response':r,'expected':expected,'actual':f"HTTP {r['status']}",'verdict':verdict,'timestamp':now(),'source':'World Monitor target','description':expected}
        ev['evidence_sha256']=sha(json.dumps(ev,sort_keys=True,separators=(',',':')));audit(ev);results.append(ev)
    return results

def counts(results):return {k:sum(1 for x in results if x['verdict']==k) for k in ('PASS','FAIL','REVIEW','ERROR','MANUAL')}

def save_run(target,results):
    state=load_state();state['last_run']=now();state['last_target']=target;state['last_results']=results
    for ev in results:
        if ev['verdict']=='FAIL':state['findings'][ev['id']]=make_finding(ev)
    save_json(STATE,state);hist=load_json(HISTORY,[]);hist.insert(0,{'id':'SCAN-'+datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f'),'timestamp':state['last_run'],'target':target,'counts':counts(results),'results':results});save_json(HISTORY,hist[:50]);return state

def lab_retest(regression=False):
    fixed=load_json(os.path.join(ROOT,'assessment_lab/lab_state.json'),{}).get('fixed',False);status=403 if fixed else 200
    cvss={'score':9.1,'severity':'Critical','vector':'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'}
    out={'finding_id':'LAB-AUTHZ-001','title':'Synthetic Broken Access Control','source':'Assessment Lab','component':'GET /admin','request':'GET /admin','response':f'HTTP {status}','expected':'HTTP 403 Forbidden','actual':f'HTTP {status}','verdict':'PASS / RESOLVED' if fixed else 'FAIL / OPEN','severity':cvss['severity'] if not fixed else 'Resolved','cvss':cvss,'regression':regression,'timestamp':now()};out['evidence_sha256']=sha(json.dumps(out,sort_keys=True,separators=(',',':')));audit(out);return out

def _e(s):return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')
def report_html(state):
    rows=''.join(f"<tr><td>{_e(f.get('id'))}</td><td>{_e(f.get('title'))}</td><td>{_e(f.get('severity'))}</td><td>{_e(f.get('status'))}</td><td>{_e((f.get('cvss') or {}).get('score','—'))}</td></tr>" for f in state.get('findings',{}).values())
    return f'''<!doctype html><html><head><meta charset="utf-8"><title>SentinelScan Security Report</title><style>body{{font-family:Arial;margin:40px;color:#172033}}h1{{color:#0b5cff}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccd4df;padding:9px;text-align:left}}.box{{padding:15px;border:1px solid #ccd4df;margin:15px 0}}</style></head><body><h1>SentinelScan Security Assessment</h1><div class="box"><b>Target:</b> {_e(state.get('last_target','—'))}<br><b>Last scan:</b> {_e(state.get('last_run','—'))}</div><h2>Findings</h2><table><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>CVSS</th></tr>{rows or '<tr><td colspan="5">No confirmed findings recorded.</td></tr>'}</table><h2>Assessment statement</h2><p>This report is generated from SentinelScan evidence. The controlled Assessment Lab is separate from the actual World Monitor target and must not be represented as a real World Monitor vulnerability.</p></body></html>'''

class H(BaseHTTPRequestHandler):
    def _json(self,status,obj):
        b=json.dumps(obj).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(b)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(b)
    def _require_auth(self):
        if not token_ok(self):self._json(401,{'error':'unauthorized'});return False
        return True
    def do_GET(self):
        if self.path=='/api/health':return self._json(200,{'ok':True,'service':'SentinelScan','time':now()})
        if self.path=='/api/audit/verify':
            if not self._require_auth():return
            return self._json(200,verify_chain())
        if self.path=='/api/audit/anchor':
            if not self._require_auth():return
            return self._json(200,{'anchor':load_json(ANCHOR,None),'verification':verify_audit_anchor()})
        if self.path in ('/api/state','/api/history','/api/report'):
            if not self._require_auth():return
            if self.path=='/api/state':return self._json(200,load_state())
            if self.path=='/api/history':return self._json(200,load_json(HISTORY,[]))
            b=report_html(load_state()).encode();self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(b)));self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'none'; style-src 'unsafe-inline'");self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(b);return
        if self.path=='/app.js':
            p=os.path.join(ROOT,'frontend/app.js');b=open(p,'rb').read();self.send_response(200);self.send_header('Content-Type','application/javascript; charset=utf-8');self.send_header('Content-Length',str(len(b)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(b);return
        if self.path=='/':
            p=os.path.join(ROOT,'frontend/index.html');b=open(p,'rb').read();self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(b)));self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'unsafe-inline'; script-src 'self' https://cdn.jsdelivr.net; connect-src 'self' https://raw.githubusercontent.com; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer');self.end_headers();self.wfile.write(b);return
        self._json(404,{'error':'not found'})
    def do_POST(self):
        if not self._require_auth():return
        if not origin_ok(self):return self._json(403,{'error':'origin not allowed'})
        try:n=int(self.headers.get('Content-Length','0') or 0)
        except ValueError:return self._json(400,{'error':'invalid content length'})
        if n>65536:return self._json(413,{'error':'body too large'})
        raw=self.rfile.read(n)
        if self.path=='/api/check':
            try:target=json.loads(raw or '{}')['target']
            except Exception:return self._json(400,{'error':'target is required'})
            if not isinstance(target,str) or len(target)>2048:return self._json(400,{'error':'invalid target'})
            tgt,err=resolve_loopback(target.rstrip('/'))
            if tgt is None:return self._json(400,{'error':err})
            results=check(target);state=save_run(target,results);return self._json(200,{'target':target,'results':results,'counts':counts(results),'state':state})
        if self.path=='/api/lab/retest':return self._json(200,lab_retest())
        if self.path=='/api/lab/fix':save_json(os.path.join(ROOT,'assessment_lab/lab_state.json'),{'fixed':True});return self._json(200,lab_retest())
        if self.path=='/api/lab/regression':return self._json(200,lab_retest(regression=True))
        self._json(404,{'error':'not found'})
    def log_message(self,*a):pass

if __name__=='__main__':
    print(f'[SentinelScan] listening on http://{HOST}:{PORT}')
    print(f'[SentinelScan] bearer token (store in dashboard): {SESSION_TOKEN}')
    print(f'[SentinelScan] token file: {TOKEN_FILE} (chmod 600)')
    print(f'[SentinelScan] audit anchor: {ANCHOR}')
    ThreadingHTTPServer((HOST,PORT),H).serve_forever()
