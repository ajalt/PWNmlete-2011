import SocketServer
import hashlib
import netsecurity

cookie = None
host, port = 'localhost', 9999

class CommandError(Exception): pass
class IncorrectChecksumError(Exception):pass

class MyTCPHandler(SocketServer.StreamRequestHandler):
    def write(self, data):
        print 'outcoming>>>', data.strip()
        self.wfile.write(data)

    def handle(self):
        # self.rfile is a file-like object created by the handler;
        # we can now use e.g. readline() instead of raw recv() calls

        # Likewise, self.wfile is a file-like object used to write back
        # to the client
        #self.wfile.write(self.data.upper())
        for directive in self.rfile:
            print 'incoming>>>:', directive.strip()
            command, args = [i.strip() for i in directive.split(':', 1)]
            if command == 'PARTICIPANT_PASSWORD_CHECKSUM':
                calcchecksum = hashlib.sha1(netsecurity.password).hexdigest()
                receivedchecksum = args.strip()
                if calcchecksum != receivedchecksum:
                    #raise IncorrectChecksumError()
                    print '***Checksum does not match:'
                    print "\tCalculated:\t", calcchecksum
                    print "\tReceived:\t", receivedchecksum
            elif command == 'REQUIRE':
                if args == 'IDENT':
                    self.write("IDENT %s\n" % netsecurity.ident)
                elif args == 'QUIT':
                    self.write("QUIT\n")
                elif args == 'ALIVE':
                    global cookie
                    if cookie is None:
                        with open(netsecurity.cookiefile, 'r') as f:
                            cookie = f.read().strip()
                    self.write("ALIVE %s\n" % cookie)
        
print 'Server listening on port %s.' % port
server = SocketServer.TCPServer((host, port), MyTCPHandler)
server.serve_forever()
