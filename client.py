import socket
import urllib2

class CommandError(Exception): pass

host, port = 'helios.ececs.uc.edu', 8180
password = '1a3e1f2bc98def7'
ident = 'IDENT'
server_port = 9999
cookie = None
cookiefile = 'cookie.txt'

def handle(data):
    global cookie
    for directive in data.strip().split('\n'):
        command, args = [i.strip() for i in directive.split(':', 1)]
        if command == 'REQUIRE':
            if args == 'IDENT':
                return 'IDENT %s' % ident
            if args == 'PASSWORD':
                return 'PASSWORD ' + password
            if args == 'HOST_PORT':
                return 'HOST_PORT %s %s' % (external_ip, server_port)
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
        if command == 'COMMAND_ERROR':
            raise CommandError(args)


if __name__ == '__main__':
    #find out external ip address for server
    #external_ip = urllib2.urlopen('http://automation.whatismyip.com/n09230945.asp').read()
    #use localhost with an ssh tunnel
    external_ip = 'localhost'
    
    # Create a socket (SOCK_STREAM means a TCP socket)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to server and send data
    sock.connect((host, port))
    
    # Receive data from the server and shut down
    while True:
        data = sock.recv(1024)
        print repr(data)
        if not data.strip():
            break
        send_data = handle(data)
        if send_data is not None:
            print 'sending:', repr(send_data + '\n')
            sock.send(send_data + '\n')
            
    sock.close()

