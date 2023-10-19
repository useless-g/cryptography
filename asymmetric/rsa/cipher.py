import random
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
        for i in range(1, 257):
            if res[-i] == 128:
                return res[1:-i]
        return res[1:]
    return inner


class RSA:
    def __init__(self,
                 cipher_key: Literal["public", "private"] = "public",
                 # key_len_bits : Literal[2048, 4096] = 2048,
                 key: Union[None, Tuple[Tuple[int, int], Tuple[int, int]]] = None) -> None:
        """
        :param cipher_key: indicate which keys - public or private, it will use to cipher
        :param key: a pair of private and public keys ((d, n), (e, n)), by default they will be generated
        """
        self.key_len_bits = ( len(hex(key[0][0])) - 2) // 2 if key else 2048
        assert self.key_len_bits in (2048, 4096)
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

    def n_bit_random(self):
        """
        Returns a random number
        between 2**(n-1)+1 and 2**n-1
        """
        n = self.key_len_bits // 2
        return random.randrange(2 ** (n - 1) + 1, 2 ** n - 1)

    def get_low_level_prime(self):
        first_primes_list = first_100_primes_list
        while True:
            prime_candidate = self.n_bit_random()

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

    def cipher_block(self, text: int):
        return fast_pow_mod(text, self.private_key[0], self.private_key[1]) if self.cipher_key == "private" \
            else fast_pow_mod(text, self.public_key[0], self.public_key[1])  # self.cipher_key == "public"

    def decipher_block(self, cipher_text: bytes):
        cipher_text = int.from_bytes(cipher_text, 'big')
        return fast_pow_mod(cipher_text, self.private_key[0], self.private_key[1]).to_bytes(256, 'big') if self.cipher_key == "public" \
            else fast_pow_mod(cipher_text, self.public_key[0], self.public_key[1]).to_bytes(256, 'big')  # self.cipher_key == "private"

    def cipher(self, big_text_bytes: bytes):
        # print("openedtext:", (len(big_text) - 2) / 2, hex(big_text))
        cur_len = len(big_text_bytes)
        big_text = (128 << cur_len * 8)
        big_text += int.from_bytes(big_text_bytes, 'big')
        block_size = self.key_len_bits
        cur_len = len(bin(big_text)) - 2

        if cur_len % block_size:
            big_text <<= 1
            big_text += 1
            big_text <<= block_size - ((cur_len+1) % block_size)
        else:
            big_text <<= 1
            big_text += 1
            big_text <<= block_size - 1

        cur_len = len(bin(big_text)) - 2

        res = 128
        while cur_len:
            block = (big_text << block_size) >> cur_len
            print("block", block.to_bytes(256, 'big'))
            big_text >>= block_size
            res <<= block_size
            res += self.cipher_block(block)
            cur_len -= block_size
        return res.to_bytes((len(hex(res)) - 2) // 2, 'big')[1:]

    @discard_padding
    def decipher(self, big_cipher_text_bytes: bytes):
        # print("ciphertext:", (len(big_cipher_text)) - 2) / 2, hex(big_cipher_text))
        # cur_len = len(big_cipher_text_bytes)
        # big_cipher_text = (128 << cur_len * 8)
        # big_cipher_text += int.from_bytes(big_cipher_text_bytes, 'big')

        block_size_bytes = self.key_len_bits // 8
        cur_len = len(big_cipher_text_bytes)

        res = bytes(0)
        start = 0
        while cur_len:
            block = big_cipher_text_bytes[start:block_size_bytes + start]
            # print("dlock", block)
            start += block_size_bytes
            deciphered = self.decipher_block(block)
            res += deciphered
            # print("dbres", deciphered)
            cur_len -= block_size_bytes

        return res


if __name__ == "__main__":
    t = time()
    Alice = RSA(cipher_key="public")
    c = Alice.cipher(('Hello, world!' * int(100)).encode('ascii'))
    deciphered_text = Alice.decipher(c)
    print(deciphered_text)
    # print("deciphtext:", len(deciphered_text), deciphered_text.decode('ascii'))
    print(f"time spent: {time() - t}")
