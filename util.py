import karn

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

