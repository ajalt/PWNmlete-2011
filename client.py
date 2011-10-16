import socket
import contextlib

import constants
import diffie_hellman
import karn

# use ssh tunnel. see wiki for instructions
host, port = 'localhost', 8170
server_addr, server_port = 'localhost', 9999
cookie = None

def process_monitor_directive(line):
    """takes directive and returns command if response is needed"""
    global cookie
    
    if ':' not in line:
        #line is probably encrypted, decrypt it and continue as normal
        line = karn.decrypt(line)
        print 'decrypted:::', line
        #return for now since decryption doesn't work yet.
        return
        
    directive, args = [i.strip() for i in line.split(':', 1)]
    if directive == 'REQUIRE':
        if args == 'IDENT':
            return 'IDENT %s %s\n' % (constants.ident, diffie_hellman.public_key)
        elif args == 'PASSWORD':
            return 'PASSWORD %s\n' % constants.password
        elif args == 'HOST_PORT':
            return 'HOST_PORT %s %s\n' % (server_addr, server_port)
        elif args == 'ALIVE':
            if cookie is None:
                with open(constants.cookiefile, 'r') as f:
                    cookie = f.read().strip()
            return 'ALIVE %s\n' % cookie
    elif directive == 'RESULT':
        args = args.split()
        if args[0] == 'PASSWORD':
            cookie = args[1]
            with open(constants.cookiefile, 'w') as f:
                f.write(cookie)
        if args[0] == 'IDENT':
            diffie_hellman.server_key = int(args[1], 32)

# Connect to server and open stream
with contextlib.closing(socket.create_connection((host, port))) as sock:
    for line in sock.makefile():
        print 'incoming>>>', line.strip()
        response = process_monitor_directive(line)
        if response:
            print 'outgoing>>>', response.strip()
            sock.send(response)
