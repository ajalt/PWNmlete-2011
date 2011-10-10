import socket
import contextlib

import netsecurity

# use ssh tunnel
host, port = 'localhost', 8180
server_addr, server_port = 'localhost', 9999
cookie = None

#process message, returns response string if response is needed
def process_monitor_msg(line):
    global cookie
    command, args = [i.strip() for i in line.split(':', 1)]
    if command == 'REQUIRE':
        if args == 'IDENT':
            return 'IDENT %s\n' % netsecurity.ident
        elif args == 'PASSWORD':
            return 'PASSWORD %s\n' % netsecurity.password
        elif args == 'HOST_PORT':
            return 'HOST_PORT %s %s\n' % (server_addr, server_port)
        elif args == 'ALIVE':
            if cookie is None:
                with open(netsecurity.cookiefile, 'r') as f:
                    cookie = f.read().strip()
            return 'ALIVE %s\n' % cookie
    elif command == 'RESULT':
        args = args.split()
        if args[0] == 'PASSWORD':
            cookie = args[1]
            with open(netsecurity.cookiefile, 'w') as f:
                f.write(cookie)

# Connect to server and open stream
with contextlib.closing(socket.create_connection((host, port))) as sock:
    for line in sock.makefile():
        print 'incoming>>>', line.strip()
        response = process_monitor_msg(line)
        if response:
            print 'outgoing>>>' + response.strip()
            sock.send(response)

#sock.close()
