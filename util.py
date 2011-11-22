import sys
import sqlite3
import hashlib
import random

import karn

#http://stackoverflow.com/questions/2267362/convert-integer-to-a-string-in-a-given-numeric-base-in-python
def baseN(num, b, numerals='0123456789abcdefghijklmnopqrstuvwxyz'):
    return '0' if num == 0 else baseN(num // b, b).lstrip('0') + numerals[num % b]
    
#baseN will overflow the stack for very large numbers. It's also slower for the sake of being a one-liner.
#this version is about 40% faster in all cases, which is as fast as it's going to get with this algorithm.
def base32(num, numerals='0123456789abcdefghijklmnopqrstuvwxyz'):
    output = bytearray()
    while num > 0:
        output.extend(numerals[num % 32])
        num >>= 5
    output.reverse()
    return str(output)

    
def is_encrypted(line):
    return line.startswith('1a')

def print_decryption_debug_info(e):
    print
    print 'Unable to decrypt!'
    print 'got: ' + repr(e.decrypted)
    print 'original cipher text: ' + repr(e.ciphertext.strip())
    print 'using key: %r' % e.key

def bytestohex(bindata):
    return ''.join('%02x' % byte for byte in bindata)

def left(string):
    return string[:len(string)//2]
    
def right(string):
    return string[len(string)//2:]
    
def inttohex(x):
    """Calculate the hex value of an int without prepending '0x' or appending 'L'
    
    Always returns an even number of characters."""
    x = '%x' % x
    return ('0' if len(x) % 2 else '') + x

def getrow(conn, ident):
    cursor = conn.cursor()
    cursor.execute('select * from players where ident=?',(ident,))
    r = cursor.fetchone()
    if not r:
        addidentrow(conn, ident)
        r = ['', '', '', '', '', '', False]
    ret = dict()
    ret['ident'] = r[0]
    ret['name'] = r[1]
    ret['team'] = r[2]
    ret['pass'] = r[3]
    ret['hash'] = r[4]
    ret['cookie'] = r[5]
    ret['loggedon'] = r[6]
    return ret

def addidentrow(conn, ident, cookie=''):
    cursor = conn.cursor()
    cursor.execute('insert into players values (?,?,?,?,?,?,?)', (ident,'','','','',cookie,False))
    conn.commit()

def updatepassword(conn, ident, password):
    cursor = conn.cursor()
    passhash = hashlib.sha1(password.upper()).hexdigest().lstrip('0')
    cursor.execute('update players set password=?,hash=? where ident=?', (password,passhash,ident))
    conn.commit()

def updatecookie(conn, ident, cookie):
    cursor = conn.cursor()
    cursor.execute('update players set cookie=? where ident=?', (cookie,ident))
    conn.commit()

def updateall(conn, ident, password, cookie):
    h = hashlib.sha1(password.upper()).hexdigest().lstrip('0') if password != '' else ''
    c = conn.cursor()
    query = 'update players set password=?, hash=?, cookie=? where ident=?'
    c.execute(query, (password, h, cookie, ident))
    conn.commit()

def getpassword(conn, ident):
    r = getrow(conn, ident)
    return r['pass'] if r else None

def getcookie(conn, ident):
    r = getrow(conn, ident)
    return r['cookie'] if r else None

def genpassword():
    return base32(random.randint(1,pow(2,64) - 1))

def getarglist(cipher):
    if len(sys.argv) > 1 and sys.argv[1] == '-e':
        if len(sys.argv) != 3:
            sys.stderr.write('expected: %s -e <encrypted argument string>\n' % sys.argv[0])
            sys.exit(1)
        return cipher.decrypt(sys.argv[2]).split()
    return None

def getpercentwin(dbconn):
    c = dbconn.cursor()
    c.execute('select count(*) from players where cookie!=?', ('',))
    owned = float(c.fetchone()[0])
    c.execute('select count(*) from players')
    total = float(c.fetchone()[0])
    return '{0:.2%}'.format(owned/total)

def getlongident(dbconn, ident):
    row = getrow(dbconn, ident)
    if row['name'] and row['team']:
        return '%s (%s, team %s): ' % (row['name'], ident, row['team'])
    else:
        return '%s: ' % ident

def getrandomport():
   port = -1
   while True:
       try:
           port = random.randint(1024,65535)
           s = socket.create_connection(('localhost',port))
           s.close()
       except:
           return port

def setloggedon(dbconn, ident, loggedon):
    c = dbconn.cursor()
    c.execute('update players set loggedon=? where ident=?', (loggedon, ident))
    dbconn.commit()
