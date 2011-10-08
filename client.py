import socket

host, port = 'helios.ececs.uc.edu', 8180
password = '1a3e1f2bc98def7'
ident = 'testing54325'
server_port = 9999
server_addr = 'localhost' #use ssh tunnel
cookie = None
cookiefile = 'cookie.txt'

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
        if args == 'PASSWORD':
            return "PASSWORD %s\n" % password
        if args == 'HOST_PORT':
            return "HOST_PORT %s %s\n" % (server_addr, server_port)
        if args == 'ALIVE':
            if cookie is None:
                with open(cookiefile, 'r') as f:
                    cookie = f.read().strip()
            return 'ALIVE %s' % cookie
    if command == 'RESULT':
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
