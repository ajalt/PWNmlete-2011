import SocketServer
import hashlib
import netsecurity

cookie = None
host, port = 'localhost', 9999

class MyTCPHandler(SocketServer.StreamRequestHandler):
    def send_command(self, command):
        print 'outgoing>>>', command.strip()
        # self.wfile is a file-like object created by the handler.
        # writing to it sends data over the TCP connection
        self.wfile.write(command.rstrip('\n') + '\n')

    def handle(self):
        # self.rfile is a file-like object created by the handler
        # reading from it gets data over the TCP connection
        for line in self.rfile:
            print 'incoming>>>:', line.strip()
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
                    self.send_command('IDENT %s' % netsecurity.ident)
                elif args == 'QUIT':
                    self.send_command('QUIT')
                elif args == 'ALIVE':
                    global cookie
                    if cookie is None:
                        with open(netsecurity.cookiefile, 'r') as f:
                            cookie = f.read().strip()
                    self.send_command('ALIVE %s' % cookie)
        
print 'Server listening on port %s.' % port
server = SocketServer.ThreadingTCPServer((host, port), MyTCPHandler)
server.serve_forever()
