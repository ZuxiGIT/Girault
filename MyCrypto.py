import Defaults
import random

pdebug = Defaults.pdebug


class RSA:
    def __init__(self, bitlen: int = 256):
        self.bitlen = bitlen
        pass

    def generate_keys(self):
        pdebug("Generating keys...")

        d = 0
        while True:
            p = get_prime(self.bitlen//2)
            pdebug(f"p = {p}")

            q = get_prime(self.bitlen//2)

            pdebug(f"\ttrying q = {q}")
            while q == p:
                q = get_prime(self.bitlen//2)
                pdebug(f"\ttrying q = {q}")

            pdebug(f"q = {q}")

            n = p * q
            pdebug(f"n = p * q = {n}")

            phi = (p - 1) * (q - 1)

            pdebug(f"phi = (p - 1) * (q - 1) = {phi}")

            e_values = [17, 257, 65537]
            e = e_values[random.randint(0, 2)]

            pdebug(f"e = {e}")

            d = inverse(e, phi)

            if d >= 0:
                break

            pdebug("d < 0 - Starting over...")

        pdebug(f"d = {d}")
        pdebug(f"e * d mod phi(n) = {e * d % n}")

        pdebug(f"Public key: {(e, n)}\tPrivate key: {(d, n)}")
        pdebug(f"Modulo: {n} = {p} * {q}")

        return (e, d, p, q, n)


first_primes = [
                2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
                53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107,
                109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
                173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
                233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283,
                293, 307, 311, 313, 317, 331, 337, 347, 349
                ]


def get_bad_prime(bitlen: int) -> int:
    while True:
        result = random.getrandbits(bitlen)

        for divisor in first_primes:
            if result % divisor == 0 and divisor ** 2 <= result:
                break
            else:
                return result


def check_miller_rabin(num: int, trial_count: int = 20) -> bool:
    max_devisions_by_two = 0
    ec = num - 1
    while ec % 2 == 0:
        ec >>= 1
        max_devisions_by_two += 1
    assert (2**max_devisions_by_two * ec == num - 1)

    def trial_composite(round_tester):
        if pow(round_tester, ec, num) == 1:
            return False
        for i in range(max_devisions_by_two):
            if pow(round_tester, 2**i * ec, num) == num - 1:
                return False
        return True

    for i in range(trial_count):
        round_tester = random.randrange(2, num)
        if trial_composite(round_tester):
            return False
    return True


def get_prime(num_length: int) -> int:
    result = get_bad_prime(num_length)
    while not check_miller_rabin(result):
        result = get_bad_prime(num_length)

    return result


def gcd(a: int, b: int) -> int:
    if a == 0:
        return b
    if b == 0 or a == b:
        return a
    if a == 1 or b == 1:
        return 1

    both_odd = True
    even_num = 0

    if a % 2 == 0:
        a >>= 1
        both_odd = False
        even_num += 1
    if b % 2 == 0:
        b >>= 1
        both_odd = False
        even_num += 1

    if both_odd:
        if a > b:
            return gcd((a - b) >> 1, b)
        if a < b:
            return gcd(a, (b - a) >> 1)
    else:
        return gcd(a, b) << (1 if even_num == 2 else 0)


def inverse(a: int, n: int) -> int:
    t = 0
    t_new = 1

    r = n
    r_new = a

    while r_new != 0:
        quotient = r // r_new
        (t, t_new) = (t_new, t - quotient * t_new)
        (r, r_new) = (r_new, r - quotient * r_new)

    if r > 1:
        return -1
    if t < 0:
        t = t + n

    return t
