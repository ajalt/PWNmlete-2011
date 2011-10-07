import SocketServer

class MyTCPHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        # self.rfile is a file-like object created by the handler;
        # we can now use e.g. readline() instead of raw recv() calls
        for line in self.rfile:
            print repr(line)
        # Likewise, self.wfile is a file-like object used to write back
        # to the client
        #self.wfile.write(self.data.upper())
        
if __name__ == '__main__':
    host, port = 'localhost', 9999

    print 'Server listening on port %s.' % port
    server = SocketServer.TCPServer((host, port), MyTCPHandler)
    server.serve_forever()