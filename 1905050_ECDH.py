import random as rand
import time as time
from sympy import randprime

params = {
    128: {
        'a': -3,
        'b': 0x000E0D4D696E6768756151750CC03A4473D03679,
        'p': 2**128 - 159,
        'gx': 0x161FF7528B899B2D0C28607CA52C5B86,
        'gy': 0xCF5AC8395BAFEB13C02DA292DDED7A83
    },
    192: {
        'a': -3,
        'b': 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
        'p': 2**192 - 2**64 - 1,
        'gx': 0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012,
        'gy': 0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811
    },
    256: {
        'a': -3,
        'b': 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
        'p': 2**256 - 2**224 + 2**192 + 2**96 - 1,
        'gx': 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
        'gy': 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    }
}

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

class Curves:
    def __init__(self, a, b, p, G):
        self.a = a
        self.b = b
        self.p = p
        self.G = G

    def checkSingularity(self, a, b, p):
        return (4 * a * a * a + 27 * b * b) % p != 0

    def generateParameters(self):
        # Generate a 128 bit prime number
        p = randprime(2**127, 2**128 - 1)

        while True :
            # Generate a random number a in range [2, p - 2]
            a = rand.randint(2, p - 2)

            # Generate 128 bit a, gx, gy randomly and then calculate b
            gx = rand.randint(2, p - 2)
            gy = rand.randint(2, p - 2)
            b = (gy * gy - gx * gx * gx - a * gx) % p

            # Check if curve is singular
            if self.checkSingularity(a, b, p):
                break

        return a, b, p, gx, gy



    def inverse(self, a, p):
        return pow(a, p - 2, p)

    def add(self, p1 : Point, p2 : Point, P):
        if p1.x == p2.x and p1.y == p2.y:
            return self.double(p1, P)
        elif p1.x == p2.x and p1.y != p2.y:
            return None
        else:
            m = ((p2.y - p1.y) * self.inverse(p2.x - p1.x, P)) % P
            x = (m * m - p1.x - p2.x) % P
            y = (m * (p1.x - x) - p1.y) % P
            return Point(x, y)

    def double(self, p : Point, P):
        m = ((3 * p.x * p.x + self.a) * self.inverse(2*p.y, P)) % P
        x = (m * m - 2 * p.x) % P
        y = (m * (p.x - x) - p.y) % P
        return Point(x, y)

    def double_and_add(self, p : Point, n, P):
        if n == 1:
            return p
        elif n % 2 == 0:
            return self.double_and_add(self.double(p, P), n // 2, P)
        else:
            return self.add(p, self.double_and_add(p, n - 1, P), P)


class ECDH(Curves):
    def __init__(self, a, b, p, G, private_key=None):
        super().__init__(a, b, p, G)
        if private_key is None:
            self.private_key = rand.randint(1, p - 1)
        else:
            self.private_key = private_key

    def extract_key(self, p : Point):
        return '0' + str(hex(p.x))[2:]


    def get_public_key(self, n):
         return self.double_and_add(self.G, n, self.p)

    def get_shared_key(self, opposite_public_key):
         return self.double_and_add(opposite_public_key, self.private_key, self.p)


def perform_ECDH(key_length):
    time_A = 0
    time_B = 0
    time_R = 0

    for i in range(5):
        A = ECDH(params[key_length]['a'], params[key_length]['b'], params[key_length]['p'], Point(params[key_length]['gx'], params[key_length]['gy']))
        B = ECDH(params[key_length]['a'], params[key_length]['b'], params[key_length]['p'], Point(params[key_length]['gx'], params[key_length]['gy']))
        R = ECDH(params[key_length]['a'], params[key_length]['b'], params[key_length]['p'], Point(params[key_length]['gx'], params[key_length]['gy']), rand.randint(1, params[key_length]['p'] - 1))

        start = time.time()
        A_public_key = A.get_public_key(A.private_key)
        end = time.time()
        time_A += (end - start) * 1000

        start = time.time()
        B_public_key = B.get_public_key(B.private_key)
        end = time.time()
        time_B += (end - start) * 1000

        start = time.time()
        R_shared_key = A.get_shared_key(B_public_key)
        end = time.time()
        time_R += (end - start) * 1000

    return time_A / 5, time_B / 5, time_R / 5



def main():
    key_lengths = [128, 192, 256]
    print("Time to compute for k = 128, 192, 256 bits")
    print("k\t\t\tA (ms)\t\t\t\tB (ms)\t\t\t\tR (ms)")

    for key_length in key_lengths:
        time_A, time_B, time_R = perform_ECDH(key_length)
        print(f"{key_length}\t\t\t{time_A:.5f}\t\t\t{time_B:.5f}\t\t\t{time_R:.5f}")

    return


if __name__ == '__main__':
    main()