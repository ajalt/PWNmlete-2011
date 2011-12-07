import random
import hashlib

######################################################################################
# THIS FILE CONTAINS OUR IMPLEMENTATION OF FIAT-SHAMIR ZERO KNOWLEDGE AUTHENTICATION #
######################################################################################

class FiatShamirError(Exception): pass

def is_prime(n, k=50):
    '''Use Miller-Rabin Primality test to test if an integer is probably prime.
    
    The probability that this test will report a prime number as composite is 4**-k'''
    if n == 2 or n == 3:
        return True
    if n < 2:
        return False
    
    #divide by some small primes first to fast track most composite numbers
    for i in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43 ,47):
        if n % i == 0:
            return False
    
    s = 1
    d = n - 1
    
    while d % 2 == 0:
        s += 1
        d = d >> 1
        
    for i in xrange(k):
        x = pow(random.randint(2,n-2), d, n)
        if x != 1 and x != n - 1:
            for _ in xrange(1, s):
                x = pow(x, 2, n)
                if x == 1:
                    return False
                if x == n - 1:
                    break
            else:
                return False
    return True

def find_prime(lower_bound, upper_bound):
    for _ in range(1000):
        n = random.randrange(lower_bound | 1, upper_bound, 2)
        if is_prime(n):
            return n
    raise FiatShamirError('Could not find a prime number.')

# created by the client to generate a public key,
# authorize set and subset j and k.
class Prover(object):
    #use static 64-bit prime keys generated with find_prime
    p = 70184992425131707181
    q = 55658916385526039923
    n = p * q
    def __init__(self):
        self.s = random.randrange(2 << 64)
        self.v = pow(self.s, 2, self.n)
        
        self.rounds = 0
        self.subset_a = ()
        
        self._r_set = ()
        
    def authorize_iter(self):
        self._r_set = tuple(random.randrange(2 << 64) for _ in xrange(self.rounds))
        for r in self._r_set:
            yield pow(r, 2, self.n)
            
    def subset_k_iter(self):
        for i in self.subset_a:
            yield (self.s * self._r_set[i]) % self.n
            
    def subset_j_iter(self):
        for i in set(xrange(self.rounds)) - set(self.subset_a):
            yield self._r_set[i] % self.n
            
# Created by the sender to check the validity of the authorize set, and subsets j and k
class Verifier(object):
    e = 65537
    #set Verifier.monitor_key to the integer representation of the result of a GET_MONITOR_KEY command
    monitor_key = None 
    
    def __init__(self, rounds, v=0, n=0):
        self.rounds = rounds
        self.v = v
        self.n = n
        
        self.authorize_set = ()
        self.subset_j = ()
        self.subset_k = ()
        
        self.subset_a = sorted(random.sample(xrange(rounds), rounds // 2))
        
    def verify_public_key(self, certificate):
        if monitor_key is None:
            raise FiatShamirError('cannot validate certificate until monitor ket is set')
            
        cert_hash = pow(certificate, Verifier.e, monitor_key)
        v_bytes = bytearray.fromhex(unicode(util.inttohex(self.v)))
        n_bytes = bytearray.fromhex(unicode(util.inttohex(self.n)))
        return hashlib.sha1(str(v_bytes) + str(n_bytes)) == cert_hash
        
    def is_valid(self, certificate=None):
        #Validates the prover's respose. If the prover's certificate is provided (as an int),
        #  then the certificate is used to verify the prover's public key.
        #  Otherwise the public key is only accepted if it is the static key used by our accounts.
        if not self.authorize_set:
            raise FiatShamirError('authorize_set cannot be empty when is_valid is called')
        if not self.subset_j:
            raise FiatShamirError('subset_j cannot be empty when is_valid is called')
        if not self.subset_k:
            raise FiatShamirError('subset_k cannot be empty when is_valid is called')
            
        if certificate is not None:
            #ensure the public key is legitimate
            if not validate_public_key(certificate):
                return False
        elif self.n != Prover.n:
            #otherwise ensure the public key is ours
            return False
            
        j = iter(self.subset_j)
        k = iter(self.subset_k)
        for i in xrange(self.rounds):
            if i in self.subset_a:
                if pow(next(k), 2, self.n) != (self.v * self.authorize_set[i]) % self.n:
                    return False
            elif pow(next(j), 2, self.n) != self.authorize_set[i]:
                    return False
        return True
    
