import socket
import sys
import contextlib
import argparse

import constants
import diffie_hellman
import karn
import util

cookie = None

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
        
    directive, args = [i.strip() for i in line.split(':', 1)]
    if directive == 'REQUIRE':
        if args == 'IDENT':
            return 'IDENT %s %s\n' % (constants.ident, util.baseN(diffie_hellman.public_key, 32))
        elif args == 'PASSWORD':
            command = 'PASSWORD %s\n' % constants.password
            return karn.encrypt(command) if Settings.encrypt else command
        elif args == 'HOST_PORT':
            command = 'HOST_PORT %s %s\n' % (Settings.server, Settings.server_port)
            return karn.encrypt(command) if Settings.encrypt else command
        elif args == 'ALIVE':
            if cookie is None:
                with open(constants.cookiefile, 'r') as f:
                    cookie = f.read().strip()
            command = 'ALIVE %s\n' % cookie
            return karn.encrypt(command) if Settings.encrypt else command
    elif directive == 'RESULT':
        args = args.split()
        if args[0] == 'PASSWORD':
            cookie = args[1]
            with open(constants.cookiefile, 'w') as f:
                f.write(cookie)
        if args[0] == 'IDENT' and Settings.encrypt:
            diffie_hellman.monitor_key = int(args[1], 32)


if __name__ == '__main__':
    parse_arguments()
    print 'Starting 0\/3r34sY NetSecurity Client'
    print 'Commands will ' + ('' if Settings.encrypt else 'not ') + 'be encrypted'

    # Connect to server and open stream
    with contextlib.closing(socket.create_connection((Settings.monitor, Settings.monitor_port))) as sock:
        for line in sock.makefile():
            print 'incoming',
            if util.is_encrypted(line):
                print '[encrypted]',
                line = karn.decrypt(line)
            print '>>>', line.strip()
            response = process_monitor_directive(line)
            if response:
                print 'outgoing',
                outgoingtext = response.strip()
                if util.is_encrypted(response):
                    print '[encrypted]',
                    outgoingtext = karn.decrypt(response).strip()
                print '>>>', outgoingtext
                sock.send(response)
