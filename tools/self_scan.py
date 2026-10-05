#!/usr/bin/env python3
"""One-pass local hardening/lifecycle smoke test for SentinelScan.

Each HTTP endpoint used by this harness is called at most once. Lab state is
reset directly in finally so cleanup never requires a second lifecycle call.
"""
import json, os, subprocess, sys, time, urllib.request, urllib.error, shutil

ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path: sys.path.insert(0,ROOT)
SERVER=os.path.join(ROOT,'backend','server.py')
TOKEN_FILE=os.path.join(ROOT,'backend','.session_token')
AUDIT=os.path.join(ROOT,'backend','sentinelscan_audit.jsonl')
ANCHOR=os.path.join(ROOT,'evidence','audit_anchor.json')
LAB_STATE=os.path.join(ROOT,'assessment_lab','lab_state.json')
BASE='http://127.0.0.1:8000'


def api(path, token=None, method='GET', body=None):
    data=json.dumps(body).encode() if body is not None else None
    headers={'Content-Type':'application/json','Origin':'http://127.0.0.1:8000'}
    if token: headers['Authorization']='Bearer '+token
    req=urllib.request.Request(BASE+path,data=data,method=method,headers=headers)
    try:
        with urllib.request.urlopen(req,timeout=5) as r:
            raw=r.read()
            try: parsed=json.loads(raw or b'{}')
            except Exception: parsed=raw.decode('utf-8','replace')
            return r.status,parsed
    except urllib.error.HTTPError as e:
        raw=e.read()
        try: parsed=json.loads(raw or b'{}')
        except Exception: parsed=raw.decode('utf-8','replace')
        return e.code,parsed


def expect(label, actual, expected):
    ok=actual==expected
    print(('PASS' if ok else 'FAIL')+f'  {label}: got {actual}, expected {expected}')
    if not ok: raise AssertionError(label)


def main():
    print('SentinelScan self-scan: one-pass local hardening + lifecycle checks')
    proc=subprocess.Popen([sys.executable,SERVER],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    try:
        deadline=time.time()+5
        while time.time()<deadline and not os.path.exists(TOKEN_FILE): time.sleep(.05)
        if not os.path.exists(TOKEN_FILE): raise RuntimeError('server did not create session token')
        token=open(TOKEN_FILE,encoding='utf-8').read().strip()

        expect('health is public',api('/api/health')[0],200)
        app_status,app_body=api('/app.js')
        expect('frontend app.js is reachable',app_status,200)
        if not isinstance(app_body,str) or not app_body.strip():
            raise AssertionError('frontend app.js response body is empty')
        print('PASS  frontend app.js body is non-empty')
        expect('state requires bearer token',api('/api/state')[0],401)
        expect('remote target is rejected',api('/api/check',token,'POST',{'target':'http://example.com'})[0],400)

        # The /api/check endpoint is intentionally called only once. The second
        # URL-shape check is performed against the same resolver used by server.py.
        from backend.server import resolve_loopback
        _,err=resolve_loopback('http://user:pass@127.0.0.1:5173/')
        if err!='userinfo not allowed': raise AssertionError('userinfo target was not rejected by resolver')
        print('PASS  userinfo target is rejected: resolver returned userinfo not allowed')

        verify_status,verify=api('/api/audit/verify',token)
        expect('audit verify endpoint is healthy',verify_status,200)
        if not verify.get('ok'): raise AssertionError('audit chain should start valid')
        print('PASS  audit chain before tamper:',verify)

        anchor_status,anchor=api('/api/audit/anchor',token)
        expect('signed audit anchor is available',anchor_status,200)
        if not anchor.get('verification',{}).get('ok'): raise AssertionError('signed audit anchor should verify')
        print('PASS  signed audit anchor verified')

        # Controlled lab lifecycle: each lab endpoint is called exactly once.
        st_open,lab_open=api('/api/lab/retest',token,'POST')
        expect('lab retest starts open',st_open,200)
        if lab_open.get('response')!='HTTP 200' or 'FAIL / OPEN' not in lab_open.get('verdict',''):
            raise AssertionError('lab should begin vulnerable')

        st_fix,lab_fixed=api('/api/lab/fix',token,'POST')
        expect('lab fix returns success',st_fix,200)
        if lab_fixed.get('response')!='HTTP 403' or 'RESOLVED' not in lab_fixed.get('verdict',''):
            raise AssertionError('lab fix should resolve')

        st_reg,lab_reg=api('/api/lab/regression',token,'POST')
        expect('lab regression returns success',st_reg,200)
        if lab_reg.get('response')!='HTTP 403': raise AssertionError('regression should remain protected')

        # Tamper the audit after its anchor was written. Verify directly through
        # the same verifier to keep /api/audit/verify a one-call endpoint test.
        if os.path.exists(AUDIT):
            backup=AUDIT+'.selfscan.bak'; shutil.copy2(AUDIT,backup)
            try:
                with open(AUDIT,'a',encoding='utf-8') as f:f.write('{"tampered":true}\n')
                from backend.server import verify_chain, verify_audit_anchor
                tampered=verify_chain()
                if tampered.get('ok') is not False: raise AssertionError('audit tamper was not detected')
                anchor_tampered=verify_audit_anchor()
                if anchor_tampered.get('ok') is not False: raise AssertionError('signed anchor did not detect audit change')
                print('PASS  audit tamper detected by chain and signed anchor')
            finally:
                shutil.move(backup,AUDIT)
            from backend.server import verify_chain, verify_audit_anchor
            restored=verify_chain(); restored_anchor=verify_audit_anchor()
            if not restored.get('ok') or not restored_anchor.get('ok'):
                raise AssertionError('audit chain/anchor did not recover after restore')
            print('PASS  audit chain + anchor recovered after restore')

        print('\nALL SELF-SCAN CHECKS PASSED')
        return 0
    finally:
        # Reset the synthetic lab without making another API call.
        try:
            if os.path.exists(LAB_STATE): os.remove(LAB_STATE)
        except OSError: pass
        proc.terminate()
        try: proc.wait(timeout=2)
        except subprocess.TimeoutExpired: proc.kill()

if __name__=='__main__': raise SystemExit(main())
