import sys
sys.path.append('../simplecrypto')


from collections import namedtuple
import json

from simplecrypto.formats import from_hex, hex, base64, from_base64
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

    @staticmethod
    def from_json(dump):
        return Identity(**json.loads(dump))

class User(object):
    """
    Represents a user with an unique master key that may have identities on
    multiple servers.
    """
    MASTER_KEY_BIT_LENGTH = 256
    RSA_KEY_BIT_LENGTH = 2048

    def __init__(self, master_key=None):
        self.master_key = master_key or crypto_random(User.MASTER_KEY_BIT_LENGTH / 8)
        self.keys_by_domain = {}

    def load_identity(self, identity):
        nonce = from_base64(identity.nonce)
        domain = identity.domain
        self.keys_by_domain[domain] = self._generate_keypair(nonce, domain)

    def get_subject(self, domain_unicode):
        core = domain_unicode.encode('utf-8') + self.master_key
        return base64(from_hex(sha256(core)))

    def build_identity(self, domain_unicode):
        nonce = crypto_random(32)

        keypair = self._generate_keypair(nonce, domain_unicode)
        self.keys_by_domain[domain_unicode] = keypair
        public_key = keypair.publickey.serialize().decode('utf-8')

        subject = self.get_subject(domain_unicode)
        revocation_key_hash = sha256(self._get_revocation_key(domain_unicode, nonce))

        return Identity(subject,
                        domain_unicode,
                        base64(nonce),
                        public_key,
                        revocation_key_hash,
                        None)

    def _generate_keypair(self, nonce, domain_unicode):
        """
        Generates a deterministic RSA keypair from a random number generator
        seed in bytes.
        """
        domain_bytes = domain_unicode.encode('utf-8')
        r = FortunaPrng()
        r.reseed(nonce + domain_bytes + self.master_key)
        return RsaKeypair(User.RSA_KEY_BIT_LENGTH, r.pseudo_random_data)

    def _get_revocation_key(self, domain_unicode, nonce):
        """
        Generates a revocation key for a given domain.
        """
        domain_bytes = domain_unicode.encode('utf-8')
        return sha256(nonce + domain_bytes + self.master_key)

    def revoke(self, identity):
        """
        Generates a revocation key for a given identity.
        """
        nonce_bytes = from_base64(identity.nonce)
        return self._get_revocation_key(identity.domain, nonce_bytes)


if __name__ == '__main__':
    # Dummy identity for serialization tests.
    i = Identity('subject',
                 'domain',
                 'nonce',
                 'public_key',
                 'revocation_key_hash',
                 'signature')

    i2 = Identity.from_json(i.to_json())
    # Make sure we can serialize and deserialize correctly.
    assert i == i2

    # Reduce RSA key size to decrease test load.
    User.RSA_KEY_BIT_LENGTH = 1024
    user = User()
    # Make sure we are generating subjects correctly.
    assert user.get_subject('domain1') == user.get_subject('domain1')
    assert user.get_subject('domain1') != user.get_subject('domain2')

    # Make sure we are building identities correctly.
    i = user.build_identity('example.com')
    assert i.domain == 'example.com'
    assert i.subject == user.get_subject('example.com')
    assert sha256(user.revoke(i)) == i.revocation_key_hash
    user_public_key = user.keys_by_domain['example.com'].publickey.serialize().decode('utf-8')
    assert user_public_key == i.public_key
    
    # Ensure private keys re-derived from identities are exactly the same
    # as the ones generated in the first place.
    user_private_key = user.keys_by_domain['example.com'].serialize()
    user.load_identity(i)
    assert user_private_key == user.keys_by_domain['example.com'].serialize()

    # Avoid dumb mistakes that include the master key in the identity.
    str_identity = i.to_json()
    assert sha256(user.master_key) not in str_identity
    assert base64(user.master_key) not in str_identity
    assert hex(user.master_key) not in str_identity
    assert user.master_key not in str_identity.encode('utf-8')
    
    # Give something for the user to see.
    print(str_identity)