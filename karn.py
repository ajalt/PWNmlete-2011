import hashlib

import diffie_hellman
import util

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
    if not util.is_encrypted(cipher_line):
        raise KarnError('"%s" is not encrypted!' % cipher_line)
    
    #convert from base 32 to bytes literal
    cipher_line = h(int(cipher_line.strip()[2:],32)).decode('hex')
    key = h(diffie_hellman.shared_secret).decode('hex')

    output = ''
    for i in xrange(0, len(cipher_line) - 1, BLOCK_SIZE):
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

def encrypt(line):
    key = h(diffie_hellman.shared_secret).decode('hex')

    output = ''
    for i in xrange(0, len(line), BLOCK_SIZE):
        chunk = line[i:i+BLOCK_SIZE]
        while len(chunk) % BLOCK_SIZE:
            chunk += '\x00'

        leftmdhex = hashlib.sha1(left(chunk) + left(key)).hexdigest()
        cipherright = h(int(leftmdhex, 16) ^ int(right(chunk).encode('hex'), 16)).decode('hex')
        rightmdhex = hashlib.sha1(cipherright + right(key)).hexdigest()
        cipherleft = h(int(rightmdhex, 16) ^ int(left(chunk).encode('hex'), 16)).decode('hex')
        output += util.baseN(int((cipherleft + cipherright).encode('hex'), 16), 32)

    output = '1a' + output + '\n'

    return output
