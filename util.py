import sqlite3
import hashlib
import random

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
        return None
    ret = dict()
    ret['ident'] = r[0]
    ret['name'] = r[1]
    ret['team'] = r[2]
    ret['pass'] = r[3]
    ret['hash'] = r[4]
    ret['cookie'] = r[5]
    return ret

def addidentrow(conn, ident):
    cursor = conn.cursor()
    cursor.execute('insert into players values (?,?,?,?,?,?)', (ident,'','','','',''))
    conn.commit()

def updatepassword(conn, ident, password):
    cursor = conn.cursor()
    passhash = hashlib.sha1(password.upper()).hexdigest()
    cursor.execute('update players set password=?,hash=? where ident=?', (password,passhash,ident))
    conn.commit()

def updatecookie(conn, ident, cookie):
    cursor = conn.cursor()
    cursor.execute('update players set cookie=? where ident=?', (cookie,ident))
    conn.commit()

def updateall(conn, ident, password, cookie):
    h = hashlib.sha1(password).hexdigest()
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


    
