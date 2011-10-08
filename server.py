import SocketServer
import hashlib

password = '1a3e1f2bc98def7'
cookiefile = 'cookie.txt'
cookie = None

class CommandError(Exception): pass
class IncorrectChecksumError(Exception):pass

class MyTCPHandler(SocketServer.StreamRequestHandler):
    def write(self, data):
        print 'Sending:', data
        self.wfile.write(data)
    def handle(self):
        # self.rfile is a file-like object created by the handler;
        # we can now use e.g. readline() instead of raw recv() calls

        # Likewise, self.wfile is a file-like object used to write back
        # to the client
        #self.wfile.write(self.data.upper())
        for directive in self.rfile:
            print 'Received:', directive
            command, args = [i.strip() for i in directive.split(':', 1)]
            if command == 'PARTICIPANT_PASSWORD_CHECKSUM':
                if hashlib.sha1(password).hexdigest() != args.strip():
                    #raise IncorrectChecksumError()
                    print 'Checksum does not match:'
                    print 'Calculated:', repr(hashlib.sha1(password).hexdigest())
                    print 'Received:', repr(args.strip())
            elif command == 'REQUIRE':
                if args == 'ALIVE':
                    global cookie
                    if cookie is None:
                        with open(cookiefile, 'r') as f:
                            cookie = f.read.strip()
                    self.write('ALIVE %s' % cookie)
        
        
if __name__ == '__main__':
    host, port = 'localhost', 9999

    print 'Server listening on port %s.' % port
    server = SocketServer.TCPServer((host, port), MyTCPHandler)
    server.serve_forever()
