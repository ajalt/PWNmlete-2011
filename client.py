import socket
import sys
import contextlib
import argparse
import sys

import constants
from diffie_hellman import Session
import karn
import util

cookie = None
mysession = None

class Settings:
    monitor = 'localhost'
    monitor_port = 8170
    server = 'localhost'
    server_port = 9999
    encrypt = True

def parse_arguments():
    parser = argparse.ArgumentParser(description='0\/3r34sY NetSecurity Client')
    parser.add_argument('--serverport', help='server port', type=int, default=Settings.server_port)
    parser.add_argument('--plaintext', help='do not encrypt lines before sending', action='store_true')
    args = parser.parse_args()
    if args.serverport:
        Settings.server_port = args.serverport
    if args.plaintext:
        Settings.encrypt = False


def process_monitor_directive(line):
    """takes directive and returns command if response is needed"""
    global cookie
    global mysession
        
    directive, args = [i.strip() for i in line.split(':', 1)]
    if directive == 'REQUIRE':
        if args == 'IDENT':
            return 'IDENT %s %s\n' % (constants.ident, util.baseN(mysession.public_key, 32))
        elif args == 'PASSWORD':
            command = 'PASSWORD %s\n' % constants.password
            return karn.encrypt(command, mysession.shared_secret) if Settings.encrypt else command
        elif args == 'HOST_PORT':
            command = 'HOST_PORT %s %s\n' % (Settings.server, Settings.server_port)
            return karn.encrypt(command, mysession.shared_secret) if Settings.encrypt else command
        elif args == 'ALIVE':
            if cookie is None:
                with open(constants.cookiefile, 'r') as f:
                    cookie = f.read().strip()
            command = 'ALIVE %s\n' % cookie
            return karn.encrypt(command, mysession.shared_secret) if Settings.encrypt else command
    elif directive == 'RESULT':
        args = args.split()
        if args[0] == 'PASSWORD':
            cookie = args[1]
            with open(constants.cookiefile, 'w') as f:
                f.write(cookie)
        if args[0] == 'IDENT' and Settings.encrypt:
            mysession.set_monitor_key(int(args[1], 32))


if __name__ == '__main__':
    parse_arguments()
    print 'Starting 0\/3r34sY NetSecurity Client'
    print 'Commands will ' + ('' if Settings.encrypt else 'not ') + 'be encrypted'

    mysession = Session()

    # Connect to server and open stream
    with contextlib.closing(socket.create_connection((Settings.monitor, Settings.monitor_port))) as sock:
        for line in sock.makefile():
            print 'incoming',
            backup = line
            if util.is_encrypted(line):
                try:
                    line = karn.decrypt(line, mysession.shared_secret)
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
                        outgoingtext = karn.decrypt(response, mysession.shared_secret).strip()
                    except karn.DecryptionError as de:
                        util.print_decryption_debug_info(de)

                print '>>>', outgoingtext
                sock.send(response)
