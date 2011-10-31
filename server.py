import SocketServer
import hashlib
import sys
import argparse
import random
import sqlite3

import diffie_hellman
import karn
import util

dbconn = None

class Settings:
    host = 'localhost'
    port = 9999
    mode = 'normal'
    encrypt = True
    debug = False
    identsdbfile = 'idents.db'
    ident = 'TESTING54329'


def parse_arguments():
    parser = argparse.ArgumentParser(description='0\/3r34sY NetSecurity Server')
    parser.add_argument('--port', help='port to listen on', type=int, default=Settings.port)
    parser.add_argument('--manual', help='run server in manual mode', action='store_true')
    parser.add_argument('--plaintext', help='do not encrypt lines before sending', action='store_true')
    parser.add_argument('--debug', help='print debug information', action='store_true')
    parser.add_argument('--ident', help='ident to use', default=Settings.ident)
    parser.add_argument('--identsdb', help='sqlite3 database for ident lookup', default=Settings.identsdbfile)
    args = parser.parse_args()
    if args.manual:
        Settings.mode = 'manual'
    if args.plaintext:
        Settings.encrypt = False
    if args.debug:
        Settings.debug = True
    Settings.port = args.port
    Settings.ident = args.ident.upper()
    Settings.identsdbfile = args.identsdb


class MyTCPHandler(SocketServer.StreamRequestHandler):
    """Handler class for our socket server
    
    It is instantiated once for every request to connect 
    to the server
    """
        
    # called once before handle() to perform initialization
    def setup(self):
        self.session = None
        self.cipher = None

        # connect to sqlite3 db
        self.dbconn = sqlite3.connect(Settings.identsdbfile)
        self.dbconn.text_factory = str

        SocketServer.StreamRequestHandler.setup(self)
       
    # called once after handle() to perform cleanup
    def finish(self):
        SocketServer.StreamRequestHandler.finish(self)
        self.dbconn.close()
    
    def check_checksum(self,checksum):
        password = util.getpassword(self.dbconn, Settings.ident)
        check = hashlib.sha1(password.upper()).hexdigest()
        if check != checksum:
            print '***Checksum does not match:'
            print '\tCalculated:\t', check
            print '\tReceived:\t', checksum

    def send_command(self, command):
        #wfile is a file-like handle to our socket
        self.wfile.write(command)
        print 'outgoing',
        outgoingtext = command.strip()
        if util.is_encrypted(command) and self.session is not None:
            print '[encrypted]',
            try:
                outgoingtext = self.cipher.decrypt(command).strip()
            except karn.DecryptionError as de:
                if Settings.debug:
                    util.print_decryption_debug_info(de)
        print '>>>', outgoingtext

    def handle(self):
        if self.session is None:
            self.session = diffie_hellman.Session()
        #rfile is a file-like handle to our socket
        for line in self.rfile:
            if util.is_encrypted(line):
                try:
                    line = self.cipher.decrypt(line)
                except karn.DecryptionError as de:
                    if Settings.debug:
                        util.print_decryption_debug_info(de)
                    continue

                print 'incoming [encrypted] >>>', line.strip()
                if Settings.debug:
                    print 'decrypted using key: %x' % self.session.shared_secret

            else:
                print 'incoming >>>', line.strip()
            directive, args = [i.strip() for i in line.split(':', 1)]
            if Settings.mode == 'manual':
                if directive == 'WAITING':
                    self.send_command(raw_input('Enter server command: ') + '\n')
            elif directive == 'PARTICIPANT_PASSWORD_CHECKSUM':
                # TODO: stop hardcoding server ident; match checksum to an ident in the database
                self.check_checksum(args.strip())
            elif directive == 'REQUIRE':
                if args == 'IDENT':
                    if Settings.encrypt:
                        self.send_command('IDENT %s %s\n' % (Settings.ident, util.baseN(self.session.public_key, 32)))
                    else:
                        self.send_command('IDENT %s\n' % Settings.ident)
                elif args == 'QUIT':
                    command = 'QUIT\n'
                    self.send_command(self.cipher.encrypt(command) if self.cipher else command)
                elif args == 'ALIVE':
                    global cookie
                    command = 'ALIVE %s\n' % util.getcookie(self.dbconn, Settings.ident)
                    self.send_command(self.cipher.encrypt(command) if self.cipher else command)
            elif directive == 'RESULT':
                args = args.split()
                if args[0] == 'IDENT' and Settings.encrypt:
                    self.session.set_monitor_key(int(args[1], 32))
                    self.cipher = karn.Cipher(self.session.shared_secret)

if __name__ == '__main__':
    parse_arguments()
    print 'Starting 0\/3r34sY NetSecurity Server'
    print 'Server listening on port %s.' % Settings.port
    print 'Server is in ' + Settings.mode + ' mode'
    print 'Commands will ' + ('' if Settings.encrypt else 'not ') + 'be encrypted'

    server = SocketServer.ThreadingTCPServer((Settings.host, Settings.port), MyTCPHandler)
    server.serve_forever()
