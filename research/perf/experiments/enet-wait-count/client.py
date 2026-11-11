"""Local JSON-RPC client; fresh connection per call and append-only evidence.

Uses only the standard library (urllib) so no third-party HTTP package is
needed. Behavior matches the requests-based original: direct connection
(no proxies), Bearer auth, Connection: close, 40 s timeout.
"""
import json
import os
from pathlib import Path
import re
import sys
import time
import urllib.request
import urllib.error

LAB=Path(__file__).resolve().parent
OUT=Path(os.environ.get('V2_EXPERIMENT_EVIDENCE',str(LAB/'evidence'))).resolve()
OUT.mkdir(parents=True,exist_ok=True)
config=json.loads((LAB/'debugger/mcp_config.json').read_text())

class _ConnectionError(Exception):
    pass


def _post(url, payload, token, timeout=40):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Authorization": "Bearer " + token,
        "Connection": "close",
        "Content-Type": "application/json",
    })
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            if resp.status >= 400:
                raise RuntimeError(f"HTTP {resp.status}")
            return json.loads(resp.read().decode())
    except urllib.error.URLError as exc:
        raise _ConnectionError(exc)


def rpc(method,params=None,timeout=40):
    request={'jsonrpc':'2.0','id':time.time_ns(),'method':method,'params':params or {}}
    value=_post(f'http://127.0.0.1:{config["Port"]}/',request,config["AuthToken"],timeout=timeout)
    with (OUT/'rpc.jsonl').open('a') as log:
        log.write(json.dumps({'time_ns':time.time_ns(),'request':request,'response':value})+'\n')
    if 'error' in value:raise RuntimeError(value['error'])
    result=value.get('result',{})
    if result.get('isError'):raise RuntimeError(result)
    return result

def call(name,args=None):
    result=rpc('tools/call',{'name':name,'arguments':args or {}})
    return '\n'.join(x['text'] for x in result.get('content',[]) if x['type']=='text')

def registers():
    return {k:int(v,16) for k,v in re.findall(r'(?m)^(e\w+): 0x([0-9A-Fa-f]+)',call('GetAllRegisters'))}

def memory(address,size):
    text=call('ReadMemory',{'address':hex(address),'size':size})
    result=bytearray()
    for line in text.splitlines():
        match=re.match(r'^\s*(?:0x)?[0-9A-Fa-f]+:\s*((?:[0-9A-Fa-f]{2}\s+)+)',line)
        if match:result.extend(bytes.fromhex(match.group(1)))
    assert len(result)==size,(text,len(result),size)
    return bytes(result)

if __name__=='__main__':
    print(call(sys.argv[1],json.loads(sys.argv[2]) if len(sys.argv)>2 else {}),flush=True)
