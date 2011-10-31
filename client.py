import socket
import sys
import contextlib
import argparse
import sqlite3

import diffie_hellman
import karn
import util

cookie = None
mysession = diffie_hellman.Session()
mycipher = None
authcomplete = False
dbconn = None

class Settings:
    monitor = 'localhost'
    monitor_port = 8160
    server = 'localhost'
    server_port = 9999
    encrypt = True
    mode = 'normal'
    identsdbfile = 'testidents.db'
    ident = 'TESTING54314'

def parse_arguments():
    parser = argparse.ArgumentParser(description='0\/3r34sY NetSecurity Client')
    parser.add_argument('--serverport', help='server port', type=int, default=Settings.server_port)
    parser.add_argument('--manual', help='run client in manual mode', action='store_true')
    parser.add_argument('--plaintext', help='do not encrypt lines before sending', action='store_true')
    parser.add_argument('--ident', help='ident to use', default=Settings.ident)
    parser.add_argument('--identsdb', help='sqlite3 database for ident lookup', default=Settings.identsdbfile)
    args = parser.parse_args()
    if args.plaintext:
        Settings.encrypt = False
    if args.manual:
        Settings.mode = 'manual'
    Settings.server_port = args.serverport
    Settings.ident = args.ident.upper()
    Settings.identsdbfile = args.identsdb


def process_monitor_directive(line):
    """takes directive and returns command if response is needed"""
    global cookie
    global mycipher
    global authcomplete
        
    directive, args = [i.strip() for i in line.split(':', 1)]
    if directive == 'WAITING' and authcomplete and Settings.mode == 'manual':
        command = raw_input('Enter command: ') + '\n'
        return mycipher.encrypt(command) if mycipher else command
    elif directive == 'REQUIRE':
        if args == 'IDENT':
            if Settings.encrypt:
                return 'IDENT %s %s\n' % (Settings.ident, util.baseN(mysession.public_key, 32))
            else:
                return 'IDENT %s\n' % Settings.ident
        elif args == 'PASSWORD':
            command = 'PASSWORD %s\n' % util.getpassword(dbconn, Settings.ident)
            return mycipher.encrypt(command) if mycipher else command
        elif args == 'HOST_PORT':
            command = 'HOST_PORT %s %s\n' % (Settings.server, Settings.server_port)
            return mycipher.encrypt(command) if mycipher else command
        elif args == 'ALIVE':
            command = 'ALIVE %s\n' % util.getcookie(dbconn, Settings.ident)
            return mycipher.encrypt(command) if mycipher else command
    elif directive == 'RESULT':
        if args == 'ALIVE Identity has been verified.':
            authcomplete = True
            return
        args = args.split()
        if args[0] == 'PASSWORD' or args[0] == 'CHANGE_PASSWORD':
            cookie = args[1]
            util.updatecookie(dbconn, Settings.ident, cookie)
        if args[0] == 'IDENT' and Settings.encrypt:
            mysession.set_monitor_key(int(args[1], 32))
            mycipher = karn.Cipher(mysession.shared_secret)


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
