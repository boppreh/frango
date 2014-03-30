from structures import Identity

import json
from simplecrypto.formats import from_base64, base64
from simplecrypto.hashes import sha256
from simplecrypto.random import random as crypto_random

class Service(object):
    """
    Class for a domain service that stores identities and is able to
    authenticate users to sessions.
    """
    SESSION_NONCE_BIT_LENGTH = 128

    def __init__(self, domain):
        """
        Creates a new empty service for the given domain.
        """
        self.domain = domain
        self.identities_by_subject = {}
        self.session_nonces = set()
        self.identity_by_session = {}

    def make_session_nonce(self):
        """
        Creates and remembers a new session nonce to be used to link an
        identity to a session.
        """
        nonce = crypto_random(SESSION_NONCE_BIT_LENGTH // 8)
        self.session_nonces.add(nonce)
        return nonce

    def register_identity(self, identity):
        """
        Registers a previously unknown identity to allow it to login.
        """
        assert identity.subject not in self.identities_by_subject
        assert identity.domain == self.domain
        assert identity.verify()
        self.identities_by_subject[identity.subject]  = identity

    def revoke_and_replace(self, old_subject, revocation_key, new_identity=None):
        """
        Revokes an old identity, optionally replacing it with a new one in
        single step.
        """
        old_identity = self.identities_by_subject[old_subject]
        assert sha256(revocation_key) == old_identity.revocation_key_hash
        del self.identities_by_subject[old_subject]

        if new_identity is not None:
            self.register_identity(new_identity)

    def fetch_identity_nonce(self, subject):
        """
        Returns the full stored identity for a given subject.
        """
        return self.identities_by_subject[subject].nonce

    def session_login(self, subject, session_nonce, signed_session_nonce):
        """
        Links an identity to a previously issued session nonce, asserting
        the user of that identity is the owner of the given session.
        """
        assert session_nonce in self.session_nonces
        identity = self.identities_by_subject[subject]
        public_key = identity.build_public_key()
        assert public_key.verify(session_nonce, from_base64(signed_session_nonce))

        self.session_nonces.remove(session_nonce)
        self.identity_by_session[session_nonce] = identity

    def session_logout(self, session_nonce):
        """
        Unlinks an identity from a session.
        """
        assert session_nonce in self.identity_by_session
        del self.identity_by_session[session_nonce]

if __name__ == '__main__':
    from simplecrypto.key import RsaKeypair
    from client import User

    service = Service('example.com')

    user = User()
    identity = user.build_identity(service.domain)

    service.register_identity(identity)
    assert service.fetch_identity_nonce(identity.subject) == identity.nonce

    session_nonce = service.make_session_nonce()
    assert session_nonce in service.session_nonces

    signed_nonce = user.sign(session_nonce, identity)
    service.session_login(identity.subject, session_none, signed_nonce)
    assert session_nonce not in service.session_nonces
    assert session_nonce in service.identity_by_session

    service.session_logout(session_nonce)
    assert session_nonce not in service.identity_by_session