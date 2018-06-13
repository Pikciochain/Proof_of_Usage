import unittest

import pikciopou.crypto as crypto


class TestCrypto(unittest.TestCase):
    """Tests the crypto module."""

    def test_random_positive_int_always_fall_with_range(self):
        rands = tuple(
            crypto.random_positive_int(5)
            for _ in range(100)
        )
        self.assertTrue(all(0 <= i <= 5 for i in rands))

    def test_get_random_hash_not_twice_the_same(self):
        self.assertNotEqual(crypto.get_hash(), crypto.get_hash())

    def test_get_hash_for_payload_always_same(self):
        self.assertEqual(crypto.get_hash('12345'), crypto.get_hash('12345'))

    def test_sign_and_verify_works_accepts_authentic_but_rejects_fraud(self):
        rsa_keys = crypto.generate_encryption_keys('pass')
        msg = 'message'
        signature = crypto.sign(msg, rsa_keys.private_key, 'pass')
        self.assertTrue(crypto.verify(msg, signature, rsa_keys.public_key))

        rsa_keys = crypto.generate_encryption_keys('pass')
        self.assertFalse(crypto.verify(msg, signature, rsa_keys.public_key))

    def test_get_closest_hash_to(self):
        closest = crypto.get_closest_hash_to(
            '99999',
            ['AAAAA', '88888', 'BBBBB', '77777']
        )
        self.assertEqual(closest, 'AAAAA')
