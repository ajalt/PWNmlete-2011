import socket

# use ssh tunnel
host, port = 'localhost', 8180
server_addr, server_port = 'localhost', 9999
password = '1a3e1f2bc98def7'
ident = 'testing54325'
cookiefile = 'cookie.txt'
cookie = None

#process message, returns response string if response is needed
def ProcessMonitorMsg(line):
    global cookie
    msgparts = line.split(':')
    if len(msgparts) != 2:
        return
    command, args = [i.strip() for i in msgparts]
    if command == 'REQUIRE':
        if args == 'IDENT':
            return "IDENT %s\n" % ident
        elif args == 'PASSWORD':
            return "PASSWORD %s\n" % password
        elif args == 'HOST_PORT':
            return "HOST_PORT %s %s\n" % (server_addr, server_port)
        elif args == 'ALIVE':
            if cookie is None:
                with open(cookiefile, 'r') as f:
                    cookie = f.read().strip()
            return "ALIVE %s\n" % cookie
    elif command == 'RESULT':
        args = args.split()
        if args[0] == 'PASSWORD':
            cookie = args[1]
            with open(cookiefile, 'w') as f:
                f.write(cookie)
                # flush buffer and close file
                f.close()

# Connect to server and open stream
sock = socket.create_connection((host, port))
f = sock.makefile()

while True:
    line = f.readline().strip()
    if not line:
        break
    print "incoming>>>" + line
    response = ProcessMonitorMsg(line)
    if response:
        print "outgoing>>>" + response.strip()
        sock.send(response)

sock.close()
