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
    ident = 'TESTING22'
    mode = 'normal'
    encrypt = True
    debug = False
    identsdbfile = 'testidents.db'
    proof_rounds = 20
    silent = False
    privatekey = None
    enforcechecksums = False

def chkprint(line):
    if not Settings.silent:
        print line

def parse_arguments():
    parser = argparse.ArgumentParser(description='0\/3r34sY NetSecurity Server')
    parser.add_argument('--port', help='port to listen on', type=int, default=Settings.port)
    parser.add_argument('--manual', help='run server in manual mode', action='store_true')
    parser.add_argument('--plaintext', help='do not encrypt lines before sending', default=(not Settings.encrypt), action='store_true')
    parser.add_argument('--silent', help='do not output anything', default=Settings.silent, action='store_true')
    parser.add_argument('--privatekey', help='use given key in base32 as private key for diffie helman', default=Settings.privatekey)
    parser.add_argument('--enforcechecksums', help='drop a transaction if the checksum is incorrect', default=Settings.enforcechecksums, action='store_true')
    parser.add_argument('--debug', help='print debug information', default=Settings.debug, action='store_true')
    parser.add_argument('--ident', help='ident to use', default=Settings.ident)
    parser.add_argument('--identsdb', help='sqlite3 database for ident lookup', default=Settings.identsdbfile)
    args = parser.parse_args()
    if args.manual:
        Settings.mode = 'manual'

    Settings.port = args.port
    Settings.encrypt = not args.plaintext
    Settings.debug = args.debug
    Settings.ident = args.ident.upper()
    Settings.identsdbfile = args.identsdb
    Settings.privatekey = args.privatekey
    Settings.silent = args.silent
    Settings.enforcechecksums = args.enforcechecksums


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
        if not password:
            print '***No password in database'
            return True
        check = hashlib.sha1(password.upper()).hexdigest()
        if check != checksum:
            chkprint('***Checksum does not match:')
            chkprint('\tCalculated:\t %s' % check)
            chkprint('\tReceived:\t %s' % checksum)
            return False
        return True

    def send_command(self, command):
        #wfile is a file-like handle to our socket
        self.wfile.write(command)
        if self.cipher:
            chkprint('outgoing [encrypted] >>> %s' % self.cipher.decrypt(command).strip())
        else:
            chkprint('outgoing>>> %s' % command.strip())

    def handle(self):
        if self.session is None:
            self.session = diffie_hellman.Session(Settings.privatekey)
        #rfile is a file-like handle to our socket
        for line in self.rfile:
            if util.is_encrypted(line):
                line = self.cipher.decrypt(line)
                chkprint('incoming [encrypted] >>> %s' % line.strip())
            else:
                chkprint('incoming >>> %s' % line.strip())
            directive, args = [i.strip() for i in line.split(':', 1)]
            if Settings.mode == 'manual':
                if directive == 'WAITING':
                    self.send_command(raw_input('Enter server command: ') + '\n')
            elif directive == 'PARTICIPANT_PASSWORD_CHECKSUM':
                check = self.check_checksum(args.strip())
                # hangup if in strict mode and checksum fails
                if Settings.enforcechecksums and not check:
                    return
            elif directive == 'REQUIRE':
                if args == 'IDENT':
                    if Settings.encrypt:
                        self.send_command('IDENT %s %s\n' % (Settings.ident, util.base32(self.session.public_key)))
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
                    #accept_transfer = self.transfer_request['recipient'] in Settings.ident_whitelist
                    accept_transfer = self.verifier.is_valid()
                    chkprint(self.verifier.is_valid())
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
    chkprint('Starting 0\/3r34sY NetSecurity Server')
    chkprint('Server listening on port %s.' % Settings.port)
    chkprint('Commands will ' + ('' if Settings.encrypt else 'not ') + 'be encrypted')

    random.seed()

    server = SocketServer.ThreadingTCPServer((Settings.host, Settings.port), MyTCPHandler)
    server.serve_forever()
