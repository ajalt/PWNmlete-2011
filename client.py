import socket
import sys
import contextlib
import argparse
import sqlite3

import diffie_hellman
import karn
import fiat_shamir
import util

cookie = None
mysession = diffie_hellman.Session()
prover = fiat_shamir.Prover()
mycipher = None
authcomplete = False
dbconn = None
transfer_args = ()


class Settings:
    monitor = 'localhost'
    monitor_port = 8160
    server = 'localhost'
    server_port = 9992
    ident = 'testing3'
    encrypt = True
    mode = 'normal'
    identsdbfile = 'idents.db'
    
    
def encrypt(command):
    '''Encrypts a command if necessary.'''
    return mycipher.encrypt(command) if mycipher else command

def process_monitor_directive(line):
    """takes directive and returns command if response is needed"""
    global cookie
    global mycipher
    global authcomplete
        
    directive, args = [i.strip() for i in line.split(':', 1)]
    if directive == 'WAITING' and authcomplete and Settings.mode == 'manual':
	    global transfer_args
        if transfer_args:
            command = encrypt('TRANSFER_REQUEST %s %s FROM %s\n' % transfer_args)
            transfer_args = ()
            return command
		else:
            command = raw_input('Enter command: ') + '\n'
            return mycipher.encrypt(command) if mycipher else command
    elif directive == 'REQUIRE':
        if args == 'IDENT':
            if Settings.encrypt:
                return 'IDENT %s %s\n' % (Settings.ident, util.baseN(mysession.public_key, 32))
            else:
                return 'IDENT %s\n' % Settings.ident
        elif args == 'PASSWORD':
            return encrypt('PASSWORD %s\n' % util.getpassword(dbconn, Settings.ident))
        elif args == 'HOST_PORT':
            return encrypt('HOST_PORT %s %s\n' % (Settings.server, Settings.server_port))
        elif args == 'ALIVE':
            return encrypt('ALIVE %s\n' % util.getcookie(dbconn, Settings.ident))
        elif args == 'PUBLIC_KEY':
            #should these be transmitted in base32?
            return encrypt('PUBLIC_KEY %d %d\n' % (prover.v, prover.n))
        elif args == 'AUTHORIZE_SET':
            return encrypt('AUTHORIZE_SET %s\n' %  ' '.join(str(s) for s in prover.authorize_iter()))
        elif args == 'SUBSET_J':
            return encrypt('SUBSET_J %s\n' % ' '.join(str(s) for s in prover.subset_j_iter()))
        elif args == 'SUBSET_K':
            return encrypt('SUBSET_K %s\n' % ' '.join(str(s) for s in prover.subset_k_iter()))
    elif directive == 'RESULT':
        if args == 'ALIVE Identity has been verified.':
            authcomplete = True
        else:
            args = args.split()
            if args[0] == 'PASSWORD' or args[0] == 'CHANGE_PASSWORD':
                cookie = args[1]
                util.updatecookie(dbconn, Settings.ident, cookie)
            elif args[0] == 'IDENT' and Settings.encrypt:
                mysession.set_monitor_key(int(args[1], 32))
                mycipher = karn.Cipher(mysession.shared_secret)
            elif args[0] == 'ROUNDS':
                prover.rounds = int(args[1])
            elif args[0] == 'SUBSET_A':
                prover.subset_a = tuple(int(i) for i in args[1:])
    elif directive == 'WAITING' and authcomplete:
        global transfer_args
        if transfer_args:
            command = encrypt('TRANSFER_REQUEST %s %s FROM %s\n' % transfer_args)
            transfer_args = ()
            return command
        if Settings.mode == 'manual':
            return encrypt(raw_input('Enter server command: ') + '\n')

def parse_arguments():
    parser = argparse.ArgumentParser(description='0\/3r34sY NetSecurity Client')
    parser.add_argument('--serverport', help='server port', type=int, default=Settings.server_port)
    parser.add_argument('--manual', help='run client in manual mode', action='store_true')
    parser.add_argument('--plaintext', help='do not encrypt lines before sending', action='store_true')
    parser.add_argument('--transfer', nargs=3, metavar=('TO_IDENT', 'AMOUNT', 'FROM_IDENT'),
                        help='transfer points between accounts after authenticating')
    args = parser.parse_args()
    if args.serverport:
        Settings.server_port = args.serverport
    if args.plaintext:
        Settings.encrypt = False
    if args.manual:
        Settings.mode = 'manual'
    if args.transfer:
        global transfer_args
        transfer_args = tuple(args.transfer)

if __name__ == '__main__':
    parse_arguments()
    print 'Starting 0\/3r34sY NetSecurity Client'
    print 'Commands will ' + ('' if Settings.encrypt else 'not ') + 'be encrypted'

    # connect to sqlite3 db
    dbconn = sqlite3.connect(Settings.identsdbfile)
    dbconn.text_factory = str

    # Connect to server and open stream
    with contextlib.closing(socket.create_connection((Settings.monitor, Settings.monitor_port))) as sock:
        for line in sock.makefile():
            print 'incoming',
            if util.is_encrypted(line):
                try:
                    line = mycipher.decrypt(line)
                except karn.DecryptionError as de:
                    util.print_decryption_debug_info(de)
                    continue
                print '[encrypted]',

            print '>>>', line.strip()
            response = process_monitor_directive(line)
            if response:
                print 'outgoing',
                outgoingtext = response.strip()
                if util.is_encrypted(response):
                    print '[encrypted]',
                    try:
                        outgoingtext = mycipher.decrypt(response).strip()
                    except karn.DecryptionError as de:
                        util.print_decryption_debug_info(de)

                print '>>>', outgoingtext
                sock.send(response)
