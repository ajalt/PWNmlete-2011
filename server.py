import SocketServer
import hashlib
import sys
import argparse
import random
import sqlite3

import diffie_hellman
import fiat_shamir
import karn
import util

dbconn = None

class Settings:
    host = 'localhost'
    port = 9992
    ident = 'testing3'
    mode = 'normal'
    encrypt = True
    debug = False
    identsdbfile = 'idents.db'
    ident_whitelist = ('TESTING1', 'TSTING2', 'TESTING3')
    proof_rounds = 3


def parse_arguments():
    parser = argparse.ArgumentParser(description='0\/3r34sY NetSecurity Server')
    parser.add_argument('--port', help='port to listen on', type=int, default=Settings.port)
    parser.add_argument('--manual', help='run server in manual mode', action='store_true')
    parser.add_argument('--plaintext', help='do not encrypt lines before sending', action='store_true')
    parser.add_argument('--debug', help='print debug information', action='store_true')
    args = parser.parse_args()
    if args.port:
        Settings.port = args.port
    if args.manual:
        Settings.mode = 'manual'
    if args.plaintext:
        Settings.encrypt = False
    if args.debug:
        Settings.debug = True


class MyTCPHandler(SocketServer.StreamRequestHandler):
    """Handler class for our socket server
    
    It is instantiated once for every request to connect 
    to the server
    """
        
    # called once before handle() to perform initialization
    def setup(self):
        self.session = None
        self.cipher = None
        self.transfer_request = {}
        self.verifier = fiat_shamir.Verifier(Settings.proof_rounds)

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
                elif args == 'ROUNDS':
                    command = 'ROUNDS %d' % Settings.proof_rounds
                    self.send_command(self.cipher.encrypt(command) if self.cipher else command)
                elif args == 'SUBSET_A':
                    command = 'SUBSET_A %s' % ' '.join(str(s) for s in self.verifier.subset_a)
                    self.send_command(self.cipher.encrypt(command) if self.cipher else command)
                elif args == 'TRANSFER_RESPONSE':
                    #use a whitelist instead of spending time on calculations
                    accept_transfer = self.transfer_request['recipient'] in Settings.ident_whitelist
                    #accept_transfer = self.verifier.is_valid()
                    command = 'TRANSFER_RESPONSE %s' % ('ACCEPT' if accept_transfer else 'DECLINE')
                    self.send_command(self.cipher.encrypt(command) if self.cipher else command)
            elif directive == 'TRANSFER':
                recipient, amount, _, sender = args.split()
                self.transfer_request = {'recipient':recipient, 'amount':amount, 'sender':sender}
            elif directive == 'RESULT':
                args = args.split()
                if args[0] == 'IDENT' and Settings.encrypt:
                    self.session.set_monitor_key(int(args[1], 32))
                    self.cipher = karn.Cipher(self.session.shared_secret)
                elif args[0] == 'SUBSET_K':
                    self.verifier.subset_k = tuple(int(i) for i in args[1:])
                elif args[0] == 'SUBSET_J':
                    self.verifier.subset_j = tuple(int(i) for i in args[1:])
                elif args[0] == 'PUBLIC_KEY':
                    self.verifier.v, self.verifier.n = (int(i) for i in args[1:])
                elif args[0] == 'AUTHORIZE_SET':
                    self.verifier.authorize_set = tuple(int(i) for i in args[1:])

if __name__ == '__main__':
    parse_arguments()
    print 'Starting 0\/3r34sY NetSecurity Server'
    print 'Server listening on port %s.' % Settings.port
    print 'Server is in ' + Settings.mode + ' mode'
    print 'Commands will ' + ('' if Settings.encrypt else 'not ') + 'be encrypted'

    server = SocketServer.ThreadingTCPServer((Settings.host, Settings.port), MyTCPHandler)
    server.serve_forever()
