import SocketServer
import hashlib
import netsecurity

cookie = None
host, port = 'localhost', 9999

class MyTCPHandler(SocketServer.StreamRequestHandler):
    def write(self, data):
        print 'outgoing>>>', data.strip()
        self.wfile.write(data.rstrip('\n') + '\n')

    def handle(self):
        # self.rfile is a file-like object created by the handler;
        # we can now use e.g. readline() instead of raw recv() calls

        # Likewise, self.wfile is a file-like object used to write back
        # to the client
        for directive in self.rfile:
            print 'incoming>>>:', directive.strip()
            command, args = [i.strip() for i in directive.split(':', 1)]
            if command == 'PARTICIPANT_PASSWORD_CHECKSUM':
                calculated_checksum = hashlib.sha1(netsecurity.password.upper()).hexdigest()
                received_checksum = args.strip()
                if calculated_checksum != received_checksum:
                    print '***Checksum does not match:'
                    print '\tCalculated:\t', calculated_checksum
                    print '\tReceived:\t', received_checksum
            elif command == 'REQUIRE':
                if args == 'IDENT':
                    self.write('IDENT %s' % netsecurity.ident)
                elif args == 'QUIT':
                    self.write('QUIT')
                elif args == 'ALIVE':
                    global cookie
                    if cookie is None:
                        with open(netsecurity.cookiefile, 'r') as f:
                            cookie = f.read().strip()
                    self.write('ALIVE %s' % cookie)
        
print 'Server listening on port %s.' % port
server = SocketServer.ThreadingTCPServer((host, port), MyTCPHandler)
server.serve_forever()
