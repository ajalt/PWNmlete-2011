import SocketServer
import hashlib
import sys
import argparse

import constants
import diffie_hellman
import karn
import util

cookie = None

class Settings:
    host = 'localhost'
    port = 9999
    mode = 'normal'
    encrypt = True

def parse_arguments():
    parser = argparse.ArgumentParser(description='0\/3r34sY NetSecurity Server')
    parser.add_argument('--port', help='port to listen on', type=int, default=Settings.port)
    parser.add_argument('--manual', help='run server in manual mode', action='store_true')
    parser.add_argument('--plaintext', help='do not encrypt lines before sending', action='store_true')
    args = parser.parse_args()
    if args.port:
        Settings.port = args.port
    if args.manual:
        Settings.mode = 'manual'
    if args.plaintext:
        Settings.encrypt = False

def check_checksum(checksum):
    check = hashlib.sha1(constants.password.upper()).hexdigest()
    if check != checksum:
        print '***Checksum does not match:'
        print '\tCalculated:\t', check
        print '\tReceived:\t', checksum

class MyTCPHandler(SocketServer.StreamRequestHandler):
    """Processes incoming data over tcp"""
    
    def send_command(self, command):
        #wfile is a file-like handle to our socket
        self.wfile.write(command)
        print 'outgoing',
        outgoingtext = command.strip()
        if util.is_encrypted(command):
            print '[encrypted]',
            outgoingtext = karn.decrypt(command).strip()
        print '>>>', outgoingtext

    def handle(self):
        #rfile is a file-like handle to our socket
        for line in self.rfile:
            print 'incoming',
            if util.is_encrypted(line):
                line = karn.decrypt(line)
                print '[encrypted]',
            print '>>>', line.strip()
            directive, args = [i.strip() for i in line.split(':', 1)]
            if Settings.mode == 'manual':
                if directive == 'WAITING':
                    self.send_command(raw_input('Enter server command: ') + '\n')
            elif directive == 'PARTICIPANT_PASSWORD_CHECKSUM':
                check_checksum(args.strip())
            elif directive == 'REQUIRE':
                if args == 'IDENT':
                    if Settings.encrypt:
                        self.send_command('IDENT %s %s\n' % (constants.ident, util.baseN(diffie_hellman.public_key, 32)))
                    else:
                        self.send_command('IDENT %s\n' % constants.ident)
                elif args == 'QUIT':
                    command = 'QUIT\n'
                    self.send_command(karn.encrypt(command) if Settings.encrypt else command)
                elif args == 'ALIVE':
                    global cookie
                    if cookie is None:
                        with open(constants.cookiefile, 'r') as f:
                            cookie = f.read().strip()
                    if Settings.encrypt:
                        self.send_command(karn.encrypt('ALIVE %s\n' % cookie))
            elif directive == 'RESULT':
                args = args.split()
                if args[0] == 'IDENT' and Settings.encrypt:
                    diffie_hellman.monitor_key = int(args[1], 32)

if __name__ == '__main__':
    parse_arguments()
    print 'Starting 0\/3r34sY NetSecurity Server'
    print 'Server listening on port %s.' % Settings.port
    print 'Server is in ' + Settings.mode + ' mode'
    print 'Commands will ' + ('' if Settings.encrypt else 'not ') + 'be encrypted'

    server = SocketServer.ThreadingTCPServer((Settings.host, Settings.port), MyTCPHandler)
    server.serve_forever()
