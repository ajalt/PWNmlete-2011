import hashlib

import diffie_hellman

BLOCK_SIZE = 40

class KarnError(Exception): pass

def left(string):
    return string[:len(string)//2]
    
def right(string):
    return string[len(string)//2:]
    
def h(x):
    """Calculate the hex value of an int without prepending '0x' or appending 'L'
    
    Always returns an even number of characters."""
    x = '%x' % x
    return ('0' if len(x) % 2 else '') + x

def decrypt(cipher_line):
    if not cipher_line.startswith('1a'):
        raise KarnError('Guard byte not present in line: %s' % cipher_line)
    
    #convert from base 32 to bytes literal
    cipher_line = h(int(cipher_line.strip()[2:],32)).decode('hex')
    
    key = h(diffie_hellman.shared_secret).decode('hex')
    output = ''
    for i in xrange(0, len(cipher_line), BLOCK_SIZE):
        cipher = cipher_line[i:i+BLOCK_SIZE].ljust(BLOCK_SIZE, '0')
        md = hashlib.sha1()
        md.update(right(cipher))
        md.update(right(key))
        plaintext = h(int(md.hexdigest(), 16) ^ int(left(cipher).encode('hex'), 16)).decode('hex')

        md = hashlib.sha1()
        md.update(plaintext)
        md.update(left(key))
        plaintext += h(int(md.hexdigest(), 16) ^ int(right(cipher).encode('hex'), 16)).decode('hex')
        
        output += plaintext
    return output

