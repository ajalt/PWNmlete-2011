import sqlite3

#http://stackoverflow.com/questions/2267362/convert-integer-to-a-string-in-a-given-numeric-base-in-python
def baseN(num, b, numerals='0123456789abcdefghijklmnopqrstuvwxyz'):
    return '0' if num == 0 else baseN(num // b, b).lstrip('0') + numerals[num % b]

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
    return cursor.fetchone()

def updatepassword(conn, ident, password):
    cursor = conn.cursor()
    cursor.execute('update players set password=? where ident=?', (password,ident))
    conn.commit()

def updatecookie(conn, ident, cookie):
    cursor = conn.cursor()
    cursor.execute('update players set cookie=? where ident=?', (cookie,ident))
    conn.commit()

def getpassword(conn, ident):
    return getrow(conn, ident)[1]

def getcookie(conn, ident):
    return getrow(conn, ident)[2]
