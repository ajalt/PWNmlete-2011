import random

import constants

class Session:
    def __init__(self):
        self.secret = random.getrandbits(512)
        self.public_key = pow(constants.g, self.secret, constants.p)
        self.shared_secret = None

    def set_monitor_key(self, key):
        self.shared_secret = pow(key, self.secret, constants.p)
