import SocketServer
import hashlib
import sys
import argparse

import constants

cookie = None

class Settings:
    host = 'localhost'
    port = 9999
    mode = 'normal'

def parse_arguments():
    parser = argparse.ArgumentParser(description='0\/3r34sY NetSecurity Server')
    parser.add_argument('--port', help='port to listen on', type=int)
    parser.add_argument('--manual', help='run server in manual mode', action='store_true')
    args = parser.parse_args()
    if args.port is not None:
        Settings.port = parser.parse_args().port
    if args.manual:
        Settings.mode = 'manual'

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
            if mode == 'manual':
                if directive == 'WAITING':
                    self.send_command(raw_input('Enter server command: ') + '\n')
            elif directive == 'PARTICIPANT_PASSWORD_CHECKSUM':
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
        
class MyTCPServer(SocketServer.ThreadingTCPServer):
    def handle_error(self, request, client_address):
        print "socket error: %s:%s" % client_address

if __name__ == '__main__':
    parse_arguments()
    print 'Server listening on port %s.' % Settings.port
    print 'Server is in ' + Settings.mode + ' mode'

    server = MyTCPServer((Settings.host, Settings.port), MyTCPHandler)
    server.serve_forever()
