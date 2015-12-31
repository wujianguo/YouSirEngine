#!/usr/bin/env python
# -*- coding: utf-8 -*-


import BaseHTTPServer
import SocketServer

class YouParserHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    server_version = "YouParserHTTP/1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.send_header("Content-Length", 5)
        self.end_headers()
        self.wfile.write("hello")


def start_server(port):
    handler = YouParserHTTPRequestHandler
    httpd = SocketServer.TCPServer(("127.0.0.1", port), handler)
    httpd.serve_forever()

# if __name__ == '__main__':
#     test_start(9018)
