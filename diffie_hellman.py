import random

class Session:
    def __init__(self):
        self.p = 0x96C99B60C4F823707B47A848472345230C5B25103DC37412A701833E8FF5C567A53A41D0B37B10F0060D50F4131C57CF1FD11B6A6CB958F36B1E7D878A4C4BC7
        self.g = 0x2C900DF142E2B839E521725585A92DC0C45D6702A48004A917F74B73DB26391F20AEAE4C6797DD5ABFF0BFCAECB29554248233B5E6682CE1C73DD2148DED76C3

        self.secret = random.getrandbits(512)
        self.public_key = pow(self.g, self.secret, self.p)
        self.shared_secret = None

    def set_monitor_key(self, key):
        self.shared_secret = pow(key, self.secret, self.p)
