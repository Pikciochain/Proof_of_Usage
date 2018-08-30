"""Provides an abstraction layer over the third-party crypto functions.

In order to stay the most independent from the crypto library used here, all
the input output of this module is based on strings only. The library objects
are inflated internally from those parameters.
"""
import base64
import sys
from collections import namedtuple
from random import Random

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA3_256
from Crypto.Signature import pss


RSAKeys = namedtuple('RSAKeys', 'private_key public_key')

_random = Random()


def random_positive_int(maxsize=sys.maxsize):
    """Generates a random integer between 0 and maxsize.

    :param: maxsize: Upper bound included of the generated random integer.
    :type maxsize: int
    :returns: A random int in [1, maxsize]
    :rtype: int
    """
    return _random.randint(1, maxsize)


def generate_encryption_keys(passphrase):
    """Creates a new set of private/public keys.

    :param passphrase: The passphrase used to protect the private key.
    :type passphrase: str
    :return: a tuple of generated keys
    :rtype: RSAKeys
    """
    key = RSA.generate(2048)
    private_key = key.export_key(
        passphrase=passphrase,
        pkcs=8,
        protection="scryptAndAES128-CBC"
    )
    return RSAKeys(
        private_key.decode('utf-8'),
        key.publickey().export_key().decode('utf-8')
    )


def _get_hash_object(payload):
    """Builds a Hash object and let it digest provided payload.

    :param payload: The payload to digest.
    :type payload: str
    :return: The hash object.
    :rtype: SHA3_256_Hash
    """
    return SHA3_256.new(payload.encode())


def get_hash(payload=None):
    """Creates a hash from the provided payload.

    :param payload: Anything that can be cast as a string. If payload is None,
        a random hash will be generated.
    :returns: The generated hash.
    :rtype: str
    """
    payload = payload or random_positive_int()
    return _get_hash_object(str(payload)).hexdigest()


def sign(message, private_key, passphrase):
    """Signs provided payload using a private key.

    :param message: The data to sign. It will be hashed internally.
    :type message: str
    :param private_key: The private key to encrypt this message.
    :type private_key: str
    :param passphrase: The passphrase used to protect the private key.
    :type passphrase: str
    :return: The resulting signature.
    :rtype: str
    """
    msg_hash = _get_hash_object(message)
    rsa_key = RSA.import_key(private_key, passphrase)
    bytes_signature = pss.new(rsa_key).sign(msg_hash)
    return base64.encodebytes(bytes_signature).decode('utf-8')


def verify(message, signature, public_key):
    """Checks provided signature matches a message using a public key.

    :param message: What should have been signed with a private key.
    :type message: str
    :param signature: The resulting signature to check.
    :type signature: str
    :param public_key: The public key that should match the private key used
        to sign.
    :type public_key: str
    :return: True if the signature is authentic, False otherwise.
    :rtype: bool
    """
    try:
        bytes_signature = base64.decodebytes(signature.encode())
        rsa_key = RSA.import_key(public_key)
        msg_hash = _get_hash_object(message)
        pss.new(rsa_key).verify(msg_hash, bytes_signature)
        return True
    except (ValueError, TypeError):
        return False


def get_closest_hash_to(hash_target, hashes):
    """Returns hash from hash list with the smallest distance to target hash.

    This function assumes all the hashes are base 64 encoded.

    :param hash_target: The hash to get the closest to.
    :type hash_target: str
    :param hashes: The list of hashes that compete.
    :type hashes: list[hashes]
    :return: The hash with the smallest distance to target hash.
    :rtype: str
    """
    hash_target_int = int(hash_target, 16)
    candidates = [
        (hash_, abs(int(hash_, 16) - hash_target_int))
        for hash_ in hashes
    ]
    rankings = sorted(candidates, key=lambda candidate: candidate[1])
    return rankings[0][0]


def base64_encode(payload):
    """Encodes provided payload to base 64.

    :param payload: The payload to encode.
    :type payload: str
    :return: The encoded payload.
    :rtype: str
    """
    return base64.encodebytes(payload.encode()).decode('utf-8')


def base64_decode(payload):
    """Encodes provided payload from base 64.

    :param payload: The payload to decode.
    :type payload: str
    :return: The decoded payload.
    :rtype: str
    """
    return base64.decodebytes(payload.encode()).decode('utf-8')
