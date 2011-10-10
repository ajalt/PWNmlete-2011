import SocketServer
import hashlib

import netsecurity

cookie = None
host, port = 'localhost', 9999
outgoing_prefix = "outgoing>>>"
incoming_prefix = "incoming>>>"

class MyTCPHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        # self.rfile self.wfile are file-like objects created by the handler.
        # reading/writing from them gets/sends data over the TCP connection.
        for line in self.rfile:
            print incoming_prefix, line.strip()
            directive, args = [i.strip() for i in line.split(':', 1)]
            if directive == 'PARTICIPANT_PASSWORD_CHECKSUM':
                calculated_checksum = hashlib.sha1(netsecurity.password.upper()).hexdigest()
                received_checksum = args.strip()
                if calculated_checksum != received_checksum:
                    print '***Checksum does not match:'
                    print '\tCalculated:\t', calculated_checksum
                    print '\tReceived:\t', received_checksum
            elif directive == 'REQUIRE':
                if args == 'IDENT':
                    command = 'IDENT %s\n' % netsecurity.ident
                    self.wfile.write(command)
                    print outgoing_prefix, command.strip()
                elif args == 'QUIT':
                    command = 'QUIT\n'
                    self.wfile.write(command)
                    print outgoing_prefix, command.strip()
                elif args == 'ALIVE':
                    global cookie
                    if cookie is None:
                        with open(netsecurity.cookiefile, 'r') as f:
                            cookie = f.read().strip()
                    command = 'ALIVE %s\n' % cookie
                    self.wfile.write(command)
                    print outgoing_prefix, command.strip()
        
print 'Server listening on port %s.' % port
server = SocketServer.ThreadingTCPServer((host, port), MyTCPHandler)
server.serve_forever()
