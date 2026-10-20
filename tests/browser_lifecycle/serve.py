"""Browser lifecycle component using real Desktop Repository reads on loopback."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
from urllib.parse import urlsplit

parser=argparse.ArgumentParser()
parser.add_argument('--root',type=Path,required=True)
parser.add_argument('--evidence',type=Path,required=True)
parser.add_argument('--helper',type=Path,required=True)
parser.add_argument('--baseline',type=Path,required=True)
parser.add_argument('--database',type=Path,required=True)
args=parser.parse_args()
if args.database.exists():raise ValueError('browser database must be new')

def storage(command,*parameters):
    result=subprocess.run([str(args.helper),command,str(args.database),*map(str,parameters)],capture_output=True,text=True,check=True,timeout=15)
    return json.loads(result.stdout)

projects=storage('seed',args.evidence/'seed-inputs.json')['projects']
by_name={row['name']:row for row in projects}
gates={row['projectId']:{'armed':False,'entered':threading.Event(),'release':threading.Event()}for row in projects}
requests=[]
lock=threading.Lock()
directory=Path(__file__).parent

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*_args):pass

    def respond(self,status,value,kind='application/json'):
        data=value if isinstance(value,bytes)else json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type',kind)
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store')
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        route=urlsplit(self.path).path
        files={'/':(directory/'browser.html','text/html; charset=utf-8'),
          '/case.html':(directory/'case.html','text/html; charset=utf-8'),
          '/current.js':(args.root/'com.xsec.desktop/frontend/index.js','text/javascript; charset=utf-8'),
          '/baseline.js':(args.baseline,'text/javascript; charset=utf-8')}
        if route in files:
            path,kind=files[route];self.respond(200,path.read_bytes(),kind)
        elif route=='/stats':
            with lock:self.respond(200,{'projects':by_name,'requests':list(requests)})
        else:self.respond(404,{'error':'unknown component path'})

    def do_POST(self):
        value=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        if self.path=='/finish':
            (args.evidence/'browser-results.json').write_text(json.dumps(value,indent=2)+'\n')
            self.respond(200,{'recorded':True})
            threading.Thread(target=self.server.shutdown,daemon=True).start()
            return
        project=value['projectId']
        if project not in gates:
            self.respond(403,{'error':'project is outside this isolated read component'});return
        gate=gates[project]
        if self.path=='/control':
            action=value['action']
            if action=='pause':
                gate['entered'].clear();gate['release'].clear();gate['armed']=True
            elif action=='wait-entered':
                if not gate['entered'].wait(10):
                    self.respond(500,{'error':'read did not reach the real HTTP boundary'});return
            elif action=='release':gate['release'].set()
            elif action=='make-unavailable':storage('make-unavailable')
            elif action=='restore':storage('restore')
            else:self.respond(400,{'error':'unknown component control'});return
            self.respond(200,{'action':action});return
        if self.path!='/read-model':self.respond(404,{'error':'unknown component path'});return
        method=value['method']
        with lock:requests.append({'projectId':project,'method':method})
        if method!='xsec.binary.samples.list':
            self.respond(403,{'error':'this read component cannot perform binary operations'});return
        if gate['armed']:
            gate['armed']=False;gate['entered'].set()
            if not gate['release'].wait(20):
                self.respond(500,{'error':'test-controlled HTTP backpressure exceeded its deadline'});return
        try:
            params=value['params']
            result=storage('samples',project,params.get('cursor','0'),params['limit'])
            self.respond(200,{'content':[{'type':'text','text':json.dumps(result)}],'isError':False})
        except subprocess.CalledProcessError:
            self.respond(500,{'error':'Desktop Repository sample read failed'})

server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
server.daemon_threads=True
url='http://127.0.0.1:'+str(server.server_port)+'/'
(args.evidence/'browser-server.json').write_text(json.dumps({'url':url,'pid':os.getpid(),'boundary':'browser/HTTP/real Desktop Repository; authorization and MCP not exercised'})+'\n')
print(url,flush=True)
try:server.serve_forever()
finally:server.server_close()
