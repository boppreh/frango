import sys
sys.path.append('../simplecrypto')


from collections import namedtuple
import json

from simplecrypto.formats import from_hex, base64
from simplecrypto.hashes import sha256
from simplecrypto.key import RsaKeypair
from simplecrypto.random import random as crypto_random
from Crypto.Random.Fortuna.FortunaGenerator import AESGenerator as FortunaPrng

class Identity(namedtuple('Identity', ['subject', 'domain', 'nonce', 'public_key', 'revocation_key_hash', 'signature'])):
    """
    Auto-signed document asserting the identity of a client for a server.

    Subject -> hash(master-key + domain)
    Domain -> from server
    Nonce -> random from user
    Public Key -> rsa(random(master-key + domain + nonce))
    Revocation Key Hash -> hash(hash(nonce + domain + master key))
    """
    def to_json(self):
        return json.dumps(self._asdict())

    def __repr__(self):
        return self.to_json()

class User(object):
    """
    Represents a user with an unique master key that may have identities on
    multiple servers.
    """
    def __init__(self, master_key=None):
        self.master_key = master_key or crypto_random(64)
        self.keys_by_domain = {}

    def load_identity(self, identity):
        nonce = from_base64(identity.nonce)
        domain_bytes = identity.domain.encode('utf-8')
        self.keys_by_domain[identity.domain] = self._generate_keypair(nonce, domain_bytes)

    def get_subject(self, domain_unicode):
        core = domain_unicode.encode('utf-8') + self.master_key
        return base64(from_hex(sha256(core)))

    def build_identity(self, domain_unicode):
        domain_bytes = domain_unicode.encode('utf-8')
        nonce = crypto_random(32)

        keypair = self._generate_keypair(nonce, domain_bytes)
        self.keys_by_domain[domain_unicode] = keypair
        public_key = keypair.publickey.serialize().decode('utf-8')

        subject = self.get_subject(domain_unicode)
        revocation_key = sha256(nonce + domain_bytes + self.master_key)
        revocation_key_hash = sha256(revocation_key)

        return Identity(subject,
                        domain_unicode,
                        base64(nonce),
                        public_key,
                        revocation_key_hash,
                        None)

    def _generate_keypair(self, nonce, domain_bytes):
        """
        Generates a deterministic RSA keypair from a random number generator
        seed in bytes.
        """
        r = FortunaPrng()
        r.reseed(nonce + domain_bytes + self.master_key)
        return RsaKeypair(2048, r.pseudo_random_data)

    def _get_revocation_key(self, domain_unicode, nonce):
        """
        Generates a revocation key for a given domain.
        """
        domain_bytes = domain_unicode.encode('utf-8')
        secret = nonce + domain_bytes + self.master_key
        return sha256(secret)


if __name__ == '__main__':
    user = User()
    identity = user.build_identity('google.com')
    print(identity)