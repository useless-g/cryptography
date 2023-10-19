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
                return res[:-i]
        return None
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
        # self.key_len_bits = (len(bin(key[0][0])) - 2) if key else 2048
        self.key_len_bits = 2048
        # assert self.key_len_bits in (2048, 4096)
        self.private_key, self.public_key = key or self.generate_keys()
        self.cipher_key = cipher_key

        check = 0x6f77202c6f6c6c654821646c726f77202c6f6c6c6548216246c726f77202c6f6c6c654821646c726f77202c6f6c6c654821646
        assert check == fast_pow_mod(fast_pow_mod(check, self.private_key[0], self.private_key[1]),  # check keys
                                     self.public_key[0],
                                     self.public_key[1])
        assert check == fast_pow_mod(fast_pow_mod(check, self.public_key[0], self.public_key[1]),  # check keys
                                     self.private_key[0],
                                     self.private_key[1])

    def generate_keys(self) -> Union[None, Tuple[Tuple[int, int], Tuple[int, int]]]:
        while True:
            while True:
                p = self.get_low_level_prime()
                if self.is_Miller_Rabin_test_passed(p):
                    break
            # print(f"p = {p}")
            while True:
                q = self.get_low_level_prime()
                if q != p and self.is_Miller_Rabin_test_passed(q):
                    break
            if len(bin(n := p * q)) - 2 == 2048:
                break
        # print(f"q = {q}")

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
        assert (e * e_inverse) % phi == 1
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

    def cipher_block(self, text: bytes):
        text = int.from_bytes(text, 'big')
        return fast_pow_mod(text, self.private_key[0], self.private_key[1]).to_bytes(256, 'big') if self.cipher_key == "private" \
            else fast_pow_mod(text, self.public_key[0], self.public_key[1]).to_bytes(256, 'big')  # self.cipher_key == "public"

    def decipher_block(self, cipher_text: bytes):
        cipher_text = int.from_bytes(cipher_text, 'big')
        # cipher_text = 578791089776172078287924841073265544359778882254729774830393510436118414474740162532866697556410180917590295888033545046379324873376627348917577435525867557719290162773223152868885033273009908897361650688683242581104928881380231910159524513545643509322677433540941409178313709999183344383239549163532071184499609863163857395148837239412961358120678181909019447288926664689083711436859520792426856261083358768976380045100393916972622069354037205351475310350091370898269001332673031118363843111082350055514543965654834876474380361411019026328852815920860731944205284367332297864960143720470249130335746041418069019195
        return fast_pow_mod(cipher_text, self.private_key[0], self.private_key[1]).to_bytes(256, 'big') if self.cipher_key == "public" \
            else fast_pow_mod(cipher_text, self.public_key[0], self.public_key[1]).to_bytes(256, 'big')  # self.cipher_key == "private"

    def cipher(self, big_text_bytes: bytes):
        # print("openedtext:", (len(big_text) - 2) / 2, hex(big_text))
        block_size_bytes = self.key_len_bits // 8
        cur_len = len(big_text_bytes)
        if cur_len % block_size_bytes:
            big_text_bytes += b'\x80'
            big_text_bytes += bytes(block_size_bytes - (cur_len % block_size_bytes + 1))
        else:
            big_text_bytes += b'\x80'
            big_text_bytes += bytes(block_size_bytes - 1)
        cur_len = len(big_text_bytes)
        res = bytes(0)
        start = 0

        while cur_len:
            block = big_text_bytes[start:block_size_bytes + start]
            start += block_size_bytes
            ciphered = self.cipher_block(block)
            res += ciphered
            # print("cbres", ciphered)
            cur_len -= block_size_bytes
        return res

    @discard_padding
    def decipher(self, big_cipher_text_bytes: bytes):
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
    Alice = RSA(cipher_key="private",
                # key=((0xacd8c03c3823f8c6a172df413ec4556a4c3bccaf14184037d35599a9b285bc7a01760511f8f8b64383840d45144ab4a346d01b36bdcce6ec4c284db5ab6f3205ce957a050b136f94a1f8f05509d2124540253f1bf9755f9a249cf2b61ff13a525ec4834b39381a2bea60d671057dfefa83308ee76f1379ee3e255630dd93777b7ed68bbdb782fc8613f4017616f000c6553e86957d75ad8281ae7a95eca108f23db01b6b10345361b91574f9c84ba9584bd0492dfca1176c9ac6bf8af335511f2758edffe04a2f9f26c7bae1fcb284cead8b0f26189db186e1fc89bdfce714f0e6fb2dc85fdc688c8b6fba70a98b53b4e015c524580c3c2cc77be9b4ecafe6dd, 0xb970b92842e1e7c5c004c2473ee1e5251b0c34bbf94f186d5857416adeaef048de5e1c53040ccec1d1b328362305c6185eb43534714cfc1b572d0bfe6176a3813a9d8b655707e0af27f67b74d8b29e07fa0cd974088d0420356aa90dbeda8c9f2c333b4c45d3c3b22ee3b62ed23744f101b74674b355d47224192892c3287015084893c7c7acb9325e3eb538f8bb2e6f9ce57b03c816eae15c03e4cf1b2c5d8e36612504135bef18f48a2105b23ca604ba0f57c4b74e847c51bace61fcd07537ae53ae272a1ae1b91fd0f2203bf0368c56bd826642c59b538f370d9cd7c6bb79290cb4eb31e8d1f7c862f0ac66cee110ce8299da85887dc7629ab0566cbbc319), (0x962b8d7e807481fad906a18f3c365e30c344ee8561176d500b208f1937c22416b114be8ed5b15523dbf5e60541a3d4e916d0c8a0fb569f2c4bd1feda3753222ffafb2d5af8f02f6c296e8c94bbeb914e8280611af8b44a4ef7a47dc9808df4a2e1a3ec52f379d9da6db2f8e311a9f85cbe711e5c44e6c11699866c4eb6040cb7be7a1c72874869417fb3abbc7abf036a2f5f400fbc6900bcf2f225a8eb4363521d2bbc7638d0cbdf23fac090df368622a9b99f7fd65e3f70f870f1c863745b9637ef22ef50522cb75882cfffce7ac49630e3e9d15e3f87b0cc5a8ceced93184fdc53d43f9d46893c9c5c82b34470058486fa87bae82bfa4810be74ab13327f5, 0xb970b92842e1e7c5c004c2473ee1e5251b0c34bbf94f186d5857416adeaef048de5e1c53040ccec1d1b328362305c6185eb43534714cfc1b572d0bfe6176a3813a9d8b655707e0af27f67b74d8b29e07fa0cd974088d0420356aa90dbeda8c9f2c333b4c45d3c3b22ee3b62ed23744f101b74674b355d47224192892c3287015084893c7c7acb9325e3eb538f8bb2e6f9ce57b03c816eae15c03e4cf1b2c5d8e36612504135bef18f48a2105b23ca604ba0f57c4b74e847c51bace61fcd07537ae53ae272a1ae1b91fd0f2203bf0368c56bd826642c59b538f370d9cd7c6bb79290cb4eb31e8d1f7c862f0ac66cee110ce8299da85887dc7629ab0566cbbc319))
                )
    print(((Alice.private_key[0], Alice.private_key[1]),  (Alice.public_key[0], Alice.public_key[1])))
    print(f"keygen time spent: {time() - t}")
    msg = ('Hello, world!' * int(100)).encode('ascii')
    # msg = ('Z' * 2563).encode('ascii')
    t = time()
    c = Alice.cipher(msg)
    print(c)
    deciphered_text = Alice.decipher(c)
    print(msg)
    print(deciphered_text)
    assert msg == deciphered_text
    print(f"time spent: {time() - t}")
