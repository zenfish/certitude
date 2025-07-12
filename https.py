#!/usr/bin/env python3

# super simple https server, slightly mod'd from https://stackoverflow.com/questions/22429648/ssl-in-python3-with-httpserver

from http.server import HTTPServer,SimpleHTTPRequestHandler
import ssl

HOST      = "localhost"
PORT      = 4443
DIRECTORY = "."
KEY       = "certz/www.oz.example.com.key"
CERT      = "certz/www.oz.example.com.pem"

httpd = HTTPServer((HOST, PORT), SimpleHTTPRequestHandler)

sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# if === True, hostname must match certificate
sslctx.check_hostname = False 

sslctx.load_cert_chain(certfile=CERT, keyfile=KEY)

httpd.socket          = sslctx.wrap_socket(httpd.socket, server_side=True)

print("Fired up server on https://%s:%s, ctrl-C to quit" % (HOST, PORT))

print("( If runnin via certitude, try: https://%s:%s/cert.html?json=certz.json )" % (HOST, PORT))

httpd.serve_forever()

