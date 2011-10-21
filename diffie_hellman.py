import sys
import types
import random

#these declarations are just for code intelligence
secret_key = None
public_key = None
monitor_key = None
shared_secret = None
p = None
g = None

class _DH(types.ModuleType, object):
    def __init__(self, *args, **kw):
        super(_DH, self).__init__(*args, **kw)
        self.p = 0x96C99B60C4F823707B47A848472345230C5B25103DC37412A701833E8FF5C567A53A41D0B37B10F0060D50F4131C57CF1FD11B6A6CB958F36B1E7D878A4C4BC7
        self.g = 0x2C900DF142E2B839E521725585A92DC0C45D6702A48004A917F74B73DB26391F20AEAE4C6797DD5ABFF0BFCAECB29554248233B5E6682CE1C73DD2148DED76C3
    
        self.bit_length = 512
    
        self._secret_key = None
        self._public_key = None
        self._shared_secret = None
    
        self.monitor_key = None
    
    @property
    def secret_key(self):
        if self._secret_key is None:
            #import this here since the magic fails to do so
            import random
            self._secret_key = random.getrandbits(self.bit_length)
        return self._secret_key
    
    @property
    def public_key(self):
        if self._public_key is None:
            self._public_key = pow(self.g, self.secret_key, self.p)
        return self._public_key
    
    @property
    def shared_secret(self):
        if self.monitor_key is None:
            raise RuntimeError('monitor_key not set before calculating shared_secret')
        # we can't cache the shared secret in the server's case,
        # because the monitor will be generating new keys every time
        # it connects to our server
        self._shared_secret = pow(self.monitor_key, self.secret_key, self.p)
        return self._shared_secret
    
#magic to get the properties to appear to be part of the module
sys.modules[__name__] = _DH(__name__)
    
