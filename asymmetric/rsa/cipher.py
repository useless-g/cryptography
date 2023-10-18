import random
from enum import Enum
from time import time
from typing import Union, Tuple, Literal
from sieve import first_100_primes_list
from math import gcd
from fast_pow_mod import fast_pow_mod
from euclid_extended import euclid_extended
from functools import wraps


def discard_padding(decipher_func):
    @wraps(decipher_func)
    def inner(*args, **kwargs):
        res = decipher_func(*args, **kwargs)
        while res % 2 == 0:
            res >>= 1
        res >>= 1
        return res
    return inner


class RSA:
    def __init__(self,
                 cipher_key: Literal["public", "private"] = "public",
                 key: Union[None, Tuple[int, Tuple[int, int]]] = None) -> None:
        """
        :param cipher_key: indicate which keys - public or private, it will use to cipher
        :param key: a pair of private and public keys ((d, n), (e, n)), by default they will be generated
        """

        self.private_key, self.public_key = key or self.generate_keys()
        self.cipher_key = cipher_key

        check = 0x6f77202c6f6c6c654821646c726f77202c6f6c6c654821646c726f77202c6f6c6c654821646c726f77202c6f6c6c654821646
        assert check == fast_pow_mod(fast_pow_mod(check, self.private_key[0], self.public_key[1]),  # check keys
                                     self.public_key[0],
                                     self.public_key[1])

    def generate_keys(self) -> Union[None, Tuple[Tuple[int, int], Tuple[int, int]]]:
        while True:
            p = self.get_low_level_prime()
            if self.is_Miller_Rabin_test_passed(p):
                break
        # print(f"p = {p}")
        while True:
            q = self.get_low_level_prime()
            if self.is_Miller_Rabin_test_passed(q):
                break
        # print(f"q = {q}")
        n = p * q
        # print(f"n = {n}")
        phi = (p - 1) * (q - 1)
        # print(f"phi = {phi}")
        while True:
            e = random.randrange(2, phi)
            if gcd(phi, e) == 1:
                break
        # print(f"e = {e}")
        # e_inverse = fast_pow_mod(e, phi - 1, n)
        e_inverse = euclid_extended(e, phi)[0]
        # print(f"e_inverse = {e_inverse}")
        # print((e * e_inverse) % phi)
        # print((e * e_inverse) % n)
        d = e_inverse % phi
        # print((d * e) % phi)
        return (d, n), (e, n)

    @staticmethod
    def n_bit_random(n: int = 1024):
        # Returns a random number
        # between 2**(n-1)+1 and 2**n-1
        return random.randrange(2 ** (n - 1) + 1, 2 ** n - 1)

    def get_low_level_prime(self, n: int = 1024):
        first_primes_list = first_100_primes_list
        while True:
            prime_candidate = self.n_bit_random(n)

            for divisor in first_primes_list:
                if (prime_candidate % divisor == 0) and (divisor ** 2 <= prime_candidate):
                    break
            # If no divisor found, return value
            else:
                return prime_candidate

    @staticmethod
    def is_Miller_Rabin_test_passed(miller_rabin_candidate):
        max_divisions_by_2 = 0
        even_component = miller_rabin_candidate - 1

        while even_component % 2 == 0:
            even_component >>= 1
            max_divisions_by_2 += 1
        assert (2 ** max_divisions_by_2 * even_component == miller_rabin_candidate - 1)

        def trial_composite(round_tester_):
            if pow(round_tester_, even_component, miller_rabin_candidate) == 1:
                return False
            for i in range(max_divisions_by_2):
                if pow(round_tester_, 2 ** i * even_component, miller_rabin_candidate) == miller_rabin_candidate - 1:
                    return False
            return True

        # Set number of trials here
        number_of_Rabin_trials = 20
        for i in range(number_of_Rabin_trials):
            round_tester = random.randrange(2, miller_rabin_candidate)
            if trial_composite(round_tester):
                return False
        return True

    def cipher(self, text: int):
        while
        text = text % 2 ** (257 * 8)  # > 256 bytes
        print("opentext:", (len(hex(text)) - 2) / 2, hex(text))
        if (len(hex(text)) - 2) // 2 < 256:  # < 256 bytes
            text <<= 1
            text += 1
            text <<= 7
            text <<= (256 - (len(hex(text)) - 2) // 2) * 8
            # while (len(hex(text)) - 2) // 2 < 256:
            #     text <<= 1
            print("paddtext:", (len(hex(text)) - 2) / 2, hex(text))
            return fast_pow_mod(text, self.private_key[0], self.private_key[1]) if self.cipher_key == "private" \
                else fast_pow_mod(text, self.public_key[0], self.public_key[1])  # self.cipher_key == "public"

        else:  # = 256 bytes
            padding = 1 << 255 * 8 + 7
            if self.cipher_key == "private":
                cipher = fast_pow_mod(text, self.private_key[0], self.private_key[1]) << 256 * 8
                cipher += fast_pow_mod(padding, self.private_key[0], self.private_key[1])
            else:  # self.cipher_key == "public"
                cipher = fast_pow_mod(text, self.public_key[0], self.public_key[1]) << 256 * 8
                cipher += fast_pow_mod(text, self.public_key[0], self.public_key[1])
            return cipher


    @discard_padding
    def decipher(self, cipher_text: int):
        print("ciphtext:", (len(hex(cipher_text)) - 2) / 2, hex(cipher_text))
        return fast_pow_mod(cipher_text, self.private_key[0], self.private_key[1]) if self.cipher_key == "public" \
            else fast_pow_mod(cipher_text, self.public_key[0], self.public_key[1])  # self.cipher_key == "private"


if __name__ == "__main__":
    t = time()
    Alice = RSA("private")
    c = Alice.cipher(0x48656c6c6f2c20776f726c642148656c6c6f22323232323232348656c6c6f2c2077446f726c642148656c6c6f22323232323232348656c6c6f2c20776f726c642148656c6c6f22323232323232348656c6c6f2c20776f726c642148656c6c6f22323232323232348656c6c6f2c20776f726c642148656c6c6f22323232323232348656c6c6f2c20776f726c642148656c6c6f22323232323232348656c6c6f2c20776f726c642148656c6c6f22323232323232348656c6c6f2c7777777777777720776f726c642148656c6c6f223232323232348656c6c6f2c20776f726c642148656c6c6f22323232323232348656c6c6f2c20776f726c642148656c6c6f223)
    deciphered_text = Alice.decipher(cipher_text=c)
    print("decptext:", (len(hex(deciphered_text)) - 2) / 2, hex(deciphered_text))
    print(f"time spent: {time() - t}")
