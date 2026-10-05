#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler,HTTPServer
import json,os
class H(BaseHTTPRequestHandler):
 def do_GET(self):
  fixed=os.path.exists('assessment_lab/lab_state.json') and json.load(open('assessment_lab/lab_state.json')).get('fixed',False)
  if self.path=='/admin':
   self.send_response(403 if fixed else 200);self.send_header('Content-Type','text/plain');self.end_headers();self.wfile.write(("forbidden" if fixed else "synthetic admin marker").encode());return
  self.send_response(404);self.end_headers()
 def log_message(self,*a):pass
if __name__=='__main__': HTTPServer(('127.0.0.1',8100),H).serve_forever()
