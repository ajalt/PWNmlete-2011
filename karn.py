import hashlib

import diffie_hellman
import util

BLOCK_SIZE = 40

class KarnError(Exception): pass

class DecryptionError(KarnError):
    """Exception raised when decryption results in an unreadable string"""
    def __init__(self, ciphertext, key, decrypted):
        self.ciphertext = ciphertext
        self.key = key
        self.decrypted = decrypted

def left(string):
    return string[:len(string)//2]
    
def right(string):
    return string[len(string)//2:]
    
def h(x):
    """Calculate the hex value of an int without prepending '0x' or appending 'L'
    
    Always returns an even number of characters."""
    x = '%x' % x
    return ('0' if len(x) % 2 else '') + x

def decrypt(cipher_line, key):
    if not util.is_encrypted(cipher_line):
        raise KarnError('"%s" is not encrypted!' % cipher_line)
        
    #convert from base 32 to bytes literal
    cipherbytes = bytearray.fromhex(h(int(cipher_line.strip()[2:], 32)))
    keybytes = bytearray.fromhex(h(key))

    output = bytearray()
    for i in xrange(0, len(cipherbytes), BLOCK_SIZE):
        cipher = cipherbytes[i:i+BLOCK_SIZE]
        
        leftmd = bytearray(hashlib.sha1(right(cipher) + right(keybytes)).digest())
        leftcipher = left(cipher)
        plaintext = bytearray(leftmd[i] ^ leftcipher[i] for i in xrange(len(leftmd)))
        
        rightmd = bytearray(hashlib.sha1(plaintext + left(keybytes)).digest())
        rightcipher = right(cipher)
        plaintext.extend(bytearray(rightmd[i] ^ rightcipher[i] for i in xrange(len(rightmd))))

        output.extend(plaintext.partition('\x00')[0])

    if any(i > 127 for i in output):
        raise DecryptionError(cipher_line, key, output)
    return output

def encrypt(line, key):
    key = h(key).decode('hex')

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

    return '1a' + output + '\n'


if __name__ == '__main__':
    #cipher = '1aiulh47hv0oa2nnagc8ncoqkgjafo0lavah2r9enkbr27jbtms1d486kak700lj1b\n'
    #output = 'REQUIRE: ALIVE'
    #key = 3727833248299146790604296447739196130318284152696130303994574122293135405788885729089693801836510541801278501484014966503699425141140733304414104847666479
    
    cipher = '1atbsh2rn8i58cstkgfcus39fjvub23frqp2abs5eto5sik47atf11jc9m6b6sdo59'
    key = 6746940941645412546836751496697141376941858762362545362004785156785656218317636544282456555747198088997673372758779413561969833606853754344751231715868651
    
    print repr(decrypt(cipher, key))
