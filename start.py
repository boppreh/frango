import sys
sys.path.append('../simplecrypto')

from simplecrypto.formats import from_hex, base64
from simplecrypto.hashes import sha256
from simplecrypto.key import RsaKeypair
from simplecrypto.random import random as crypto_random
from Crypto.Random.Fortuna.FortunaGenerator import AESGenerator as FortunaPrng

from collections import namedtuple

class Identity(namedtuple('Identity', 'subject domain nonce public_key revocation_key_hash signature')):
    """
    Auto-signed document asserting the identity of a client for a server.

    Subject -> hash(master-key + domain)
    Domain -> from server
    Nonce -> random from user
    Public Key -> rsa(random(master-key + domain + nonce))
    Revocation Key Hash -> hash(hash(nonce + domain + master key))
    """
    pass

class User(object):
    """
    Represents a user with an unique master key that may have identities on
    multiple servers.
    """
    def __init__(self, master_key=None):
        self.master_key = master_key or crypto_random(64)
        self.keypairs_by_domain = {}

    def build_identity(self, domain_unicode):
        domain_bytes = domain_unicode.encode('utf-8')

        subject = sha256(self.master_key + domain_bytes)
        nonce = crypto_random(32)
        secret = nonce + domain_bytes + self.master_key
        keypair = self._generate_keypair(secret)
        revocation_key = sha256(secret)
        revocation_key_hash = sha256(revocation_key)

        return Identity(base64(from_hex(subject)),
                        domain_unicode,
                        base64(nonce),
                        keypair.publickey.serialize().decode('utf-8'),
                        revocation_key_hash,
                        None)

    def _generate_keypair(self, seed):
        """
        Generates a deterministic RSA keypair from a random number generator
        seed in bytes.
        """
        r = FortunaPrng()
        r.reseed(seed)
        return RsaKeypair(2048, r.pseudo_random_data)

    def _get_revocation_key(self, domain_unicode, nonce):
        """
        Generates a revocation key for a given domain.
        """
        domain_bytes = domain_unicode.encode('utf-8')
        secret = nonce + domain_bytes + self.master_key
        return sha256(secret)


user = User()
identity = user.build_identity('google.com')
print(identity)