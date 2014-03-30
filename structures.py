import sys
sys.path.append('../simplecrypto')


from collections import namedtuple
import json

from simplecrypto.formats import from_hex, hex, base64, from_base64
from simplecrypto.hashes import sha256
from simplecrypto.key import RsaKeypair, RsaPublicKey
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
        """
        Converts this identity to a JSON string.
        """
        return json.dumps(self._asdict())

    def __repr__(self):
        """
        Returns the JSON representation of this identity.
        """
        return self.to_json()

    def build_public_key(self):
        """
        Returns a RsaPublicKey instance extracted from this identity.
        """
        return RsaPublicKey(self.public_key)

    def verify(self):
        """
        Verifies this identity signature matches the public key declared.
        """
        self_dict = self._asdict()
        self_dict['signature'] = ''
        signatureless_identity = Identity(**self_dict)
        str_identity = signatureless_identity.to_json()
        public_key = self.build_public_key()
        return public_key.verify(str_identity, from_base64(self.signature))

    @staticmethod
    def from_json(dump):
        """
        Creates an identity from a JSON string.
        """
        return Identity(**json.loads(dump))

class User(object):
    """
    Represents a user with an unique master key that may have identities on
    multiple servers.
    """
    MASTER_KEY_BIT_LENGTH = 256
    RSA_KEY_BIT_LENGTH = 2048

    def __init__(self, master_key=None):
        """
        Creates a new user. If not given a master key, a new random one
        is generated.
        """
        self.master_key = master_key or crypto_random(User.MASTER_KEY_BIT_LENGTH // 8)
        self.keys_by_domain = {}

    def load_identity(self, identity):
        """
        Re-generates the private key for the identity domain and caches
        it in this User instance.
        """
        nonce = from_base64(identity.nonce)
        domain = identity.domain
        self.keys_by_domain[domain] = self._generate_keypair(nonce, domain)

    def get_subject(self, domain):
        """
        Returns the Base64 identifier of this user in the given domain.

        subject = sha256(domain + master key)
        """
        core = domain.encode('utf-8') + self.master_key
        return base64(from_hex(sha256(core)))

    def build_identity(self, domain):
        """
        Creates an Identity instance for this user in the given domain.
        The corresponding private key is cached in this User instance.
        """
        nonce = crypto_random(32)

        keypair = self._generate_keypair(nonce, domain)
        # Cache key pair.
        self.keys_by_domain[domain] = keypair
        # PEM-encoded public key.
        public_key = keypair.publickey.serialize().decode('utf-8')

        subject = self.get_subject(domain)
        revocation_key_hash = sha256(self._get_revocation_key(domain, nonce))

        signatureless_identity = Identity(subject,
                                          domain,
                                          base64(nonce),
                                          public_key,
                                          revocation_key_hash,
                                          '')

        signature = base64(keypair.sign(signatureless_identity.to_json()))

        return Identity(subject,
                        domain,
                        base64(nonce),
                        public_key,
                        revocation_key_hash,
                        signature)

    def _generate_keypair(self, nonce, domain):
        """
        Generates a deterministic RSA keypair from a random number generator
        seed in bytes.
        """
        domain_bytes = domain.encode('utf-8')
        # TODO: check if this usage is correct. This is a fairly internal
        # class of the PyCryto package (this is not the original class name,
        # check the import).
        r = FortunaPrng()
        r.reseed(nonce + domain_bytes + self.master_key)
        return RsaKeypair(User.RSA_KEY_BIT_LENGTH, r.pseudo_random_data)

    def _get_revocation_key(self, domain, nonce):
        """
        Generates a revocation key for a given domain.
        """
        domain_bytes = domain.encode('utf-8')
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

    # Make sure it is properly signed.
    assert i.signature
    assert i.verify()

    str_identity = i.to_json()
    # Avoid dumb mistakes that include the master key in the identity.
    assert sha256(user.master_key) not in str_identity
    assert base64(user.master_key) not in str_identity
    assert hex(user.master_key) not in str_identity
    assert user.master_key not in str_identity.encode('utf-8')
    
    # Give something for the user to see.
    print(str_identity)