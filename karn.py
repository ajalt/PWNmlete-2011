import hashlib
import random

import diffie_hellman
import util

BLOCK_SIZE = 40
GUARD_BYTE = 42
NULL_BYTE = 0

########################################################################################
# THIS FILE CONTAINS OUR IMPLEMENTATION OF KARN ENCRYPTION, A SYMMETRIC KEY CRYPTOSYSM #
########################################################################################
class KarnError(Exception): pass

class DecryptionError(KarnError):
    """Exception raised when decryption results in an unreadable string"""
    def __init__(self, ciphertext, key, decrypted):
        self.ciphertext = ciphertext
        self.key = key
        self.decrypted = decrypted

# Cipher is a class that is instantiated with an integer key from the monitor.
# the key is converted by the constructor to a bytearray identical to the monitor's key
class Cipher(object):
    def __init__(self, key):
        self.key = key
        # need to convert integer to hex str before getting the byte array
        keybytes = bytearray.fromhex(unicode(util.inttohex(key)))

        # the monitor uses Java's BigInteger, which uses 2s complement.
        # that means that it will add on a 0 byte in front to preserve the
        # sign of the key, if the most significant bit of the key is set
        if keybytes[0] & (1 << 7):
            keybytes.insert(0,0)

        # even if the key ends up being an odd number of bytes, the monitor breaks it
        # into two equal halves, and the least significant byte gets discarded.
        # probably a bug in the monitor, but that's how it is
        halfkeylen = len(keybytes) // 2
        self.leftkey = keybytes[:halfkeylen]
        self.rightkey = keybytes[halfkeylen: 2*halfkeylen]

    def decrypt(self, cipher_line):
        if not util.is_encrypted(cipher_line):
            raise KarnError('"%s" is not encrypted!' % cipher_line)
            
        # convert from base 32 to bytes literal
        cipherbytes = bytearray.fromhex(unicode(util.inttohex(int(cipher_line.strip(), 32))))

        output = bytearray()
        # start at byte 1 because byte 0 is the guard byte
        for i in xrange(1, len(cipherbytes), BLOCK_SIZE):
            cipher = cipherbytes[i:i+BLOCK_SIZE]
            
            # + is the concatenation operator in python
            # ^ is the xor operator
            leftmd = bytearray(hashlib.sha1(str(util.right(cipher)) + str(self.rightkey)).digest())
            leftcipher = util.left(cipher)
            plaintext = bytearray(leftmd[i] ^ leftcipher[i] for i in xrange(len(leftmd)))
            rightmd = bytearray(hashlib.sha1(str(plaintext) + str(self.leftkey)).digest())
            rightcipher = util.right(cipher)
            plaintext.extend(bytearray(rightmd[i] ^ rightcipher[i] for i in xrange(len(rightmd))))

            # break if we decrypted a null byte
            output.extend(plaintext.partition('\x00')[0])
            if '\x00' in plaintext:
                break

        # we are expecting an ascii string, so print debug info 
        # if any decrypted character is out of ascii range
        if any(i > 127 for i in output):
            print 'couldn\'t decrypt ciphertext: %s' % cipher_line
            print 'with key: %d' % self.key
            print 'output: %s' % output
            raise DecryptionError(cipher_line, self.key, output)

        return str(output)

    # msg is an encrypted message to be decrypted
    def encrypt(self, msg):
        msglen = len(msg)
        msgbytes = bytearray(msglen + 1 + BLOCK_SIZE - ((msglen + 1) % BLOCK_SIZE))
        msgbytes[:msglen] = msg

        # add null byte and random byte padding as necessary
        msgbytes[msglen] = NULL_BYTE
        for i in xrange(msglen + 1, len(msgbytes)):
            msgbytes[i] = random.randint(0, 255)

        output = bytearray(1)
        output[0] = GUARD_BYTE

        for i in xrange(0, len(msgbytes), BLOCK_SIZE):
            block = msgbytes[i:i+BLOCK_SIZE]

            leftblock = util.left(block)
            rightblock = util.right(block)

            leftmd = bytearray(hashlib.sha1(str(leftblock) + str(self.leftkey)).digest())
            rightcipher = bytearray(leftmd[i] ^ rightblock[i] for i in xrange(len(leftmd)))
            rightmd = bytearray(hashlib.sha1(str(rightcipher) + str(self.rightkey)).digest())
            leftcipher = bytearray(rightmd[i] ^ leftblock[i] for i in xrange(len(rightmd)))

            output.extend(leftcipher)
            output.extend(rightcipher) 

        return util.base32(int(util.bytestohex(output), 16)) + '\n'
