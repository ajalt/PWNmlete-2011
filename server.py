import SocketServer
import hashlib

import constants

# use ssh tunnel. see wiki for instructions
host, port = 'localhost', 9999
cookie = None

class MyTCPHandler(SocketServer.StreamRequestHandler):
    """Processes incoming data over tcp
    
    self.rfile self.wfile are file-like objects created by the handler.
    reading/writing from them gets/sends data over the TCP connection.
    """
    def send_command(self, command):
        self.wfile.write(command)
        print 'outgoing>>>', command.strip()

    def check_checksum(self, checksum):
        check = hashlib.sha1(constants.password.upper()).hexdigest()
        if check != checksum:
            print '***Checksum does not match:'
            print '\tCalculated:\t', check
            print '\tReceived:\t', checksum

    def handle(self):
        for line in self.rfile:
            print 'incoming>>>', line.strip()
            directive, args = [i.strip() for i in line.split(':', 1)]
            if directive == 'PARTICIPANT_PASSWORD_CHECKSUM':
                self.check_checksum(args.strip())
            elif directive == 'REQUIRE':
                if args == 'IDENT':
                    self.send_command('IDENT %s\n' % constants.ident)
                elif args == 'QUIT':
                    self.send_command('QUIT\n')
                elif args == 'ALIVE':
                    global cookie
                    if cookie is None:
                        with open(constants.cookiefile, 'r') as f:
                            cookie = f.read().strip()
                    self.send_command('ALIVE %s\n' % cookie)
        
print 'Server listening on port %s.' % port
server = SocketServer.ThreadingTCPServer((host, port), MyTCPHandler)
server.serve_forever()
