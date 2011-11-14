import random

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

class Prover(object):
    ##use static 128-bit prime keys
    #p = 684223312678793544935145963235999473023
    #q = 1120468056834988839380190802935820614931
    #just kidding, I think keys that big were causing decryption errors
    #use 64-but keys instead
    p = 70184992425131707181
    q = 55658916385526039923
    n = p * q
    def __init__(self):
        self.s = random.randrange(2 << 98, 2 << 99)
        self.v = pow(self.s, 2, self.n)
        
        self.rounds = 0
        self.subset_a = ()
        
        self._r_set = ()
        
    def authorize_iter(self):
        self._r_set = tuple(random.randrange(2 << 128) for _ in xrange(self.rounds))
        for r in self._r_set:
            print r, pow(r, 2, self.n)
            yield pow(r, 2, self.n)
            
    def subset_k_iter(self):
        for i in self.subset_a:
            yield (self.s * self._r_set[i]) % self.n
            
    def subset_j_iter(self):
        for i in set(xrange(self.rounds)) - set(self.subset_a):
            yield self._r_set[i] % self.n
            
class Verifier(object):
    def __init__(self, rounds, v=0, n=0):
        self.rounds = rounds
        self.v = v
        self.n = n
        
        self.authorize_set = ()
        self.subset_j = ()
        self.subset_k = ()
        
        self.subset_a = sorted(random.sample(xrange(rounds), rounds // 2))
        
    def is_valid(self):
        if not self.authorize_set:
            raise FiatShamirError('authorize_set cannot be empty when is_valid is called')
        if not self.subset_j:
            raise FiatShamirError('subset_j cannot be empty when is_valid is called')
        if not self.subset_k:
            raise FiatShamirError('subset_k cannot be empty when is_valid is called')
            
        #ensure the public key is ours
        if self.n != Prover.n:
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
    
