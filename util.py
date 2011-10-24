import karn

#http://stackoverflow.com/questions/2267362/convert-integer-to-a-string-in-a-given-numeric-base-in-python
def baseN(num,b,numerals="0123456789abcdefghijklmnopqrstuvwxyz"):
    return ((num == 0) and numerals[0]) or (baseN(num // b, b, numerals).lstrip(numerals[0]) + numerals[num % b])

def is_encrypted(line):
    return line.startswith('1a')

def print_decryption_debug_info(e):
    print
    print 'Unable to decrypt!'
    print 'got: ' + e.decrypted
    print 'original cipher text: ' + e.ciphertext.strip()
    print 'using key: %x' % e.key

