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
        cipher = cipher_line[i:i+BLOCK_SIZE]
        leftmdhex = hashlib.sha1((right(cipher) + right(key))).hexdigest()
        leftcipherhex = left(cipher).encode('hex')
        plaintext = h(int(leftmdhex, 16) ^ int(leftcipherhex, 16)).decode('hex')
        rightmdhex = hashlib.sha1(plaintext + left(key)).hexdigest()
        rightcipherhex = right(cipher).encode('hex')
        plaintext += h(int(rightmdhex, 16) ^ int(rightcipherhex, 16)).decode('hex')

        nullbyte = plaintext.find('\x00')
        if nullbyte != -1:
            plaintext = plaintext[:nullbyte]
        output += plaintext

    return output
