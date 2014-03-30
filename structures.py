import sys
sys.path.append('../simplecrypto')

import json
from collections import namedtuple
from simplecrypto.key import RsaPublicKey
from simplecrypto.formats import from_base64

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