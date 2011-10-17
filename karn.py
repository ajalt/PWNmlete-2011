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
        leftmd = hashlib.sha1((right(cipher) + right(key)))
        leftmdhex = leftmd.hexdigest()
        leftcipherhex = left(cipher).encode('hex')
        plaintext = ''
        for j in range(0, len(leftmdhex), 2):
            hexbyte = h(int(leftmdhex[j:j+2], 16) ^ int(leftcipherhex[j:j+2], 16))
            #check for null byte
            if hexbyte == '00':
                break
            plaintext += hexbyte.decode('hex')
        
        if len(plaintext) < len(cipher):
            output += plaintext
            break

        rightmd = hashlib.sha1(plaintext + left(key))
        rightmdhex = rightmd.hexdigest()
        rightcipherhex = right(cipher).encode('hex')
        for j in range(0, len(rightmdhex), 2):
            hexbyte = h(int(rightmdhex[j:j+2], 16) ^ int(rightcipherhex[j:j+2], 16))
            #check for null byte
            if hexbyte == '00':
                break
            plaintext += hexbyte.decode('hex')

        output += plaintext
    return output
