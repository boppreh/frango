from structures import Identity

import json
from simplecrypto.formats import from_base64, base64
from simplecrypto.hashes import sha256
from simplecrypto.random import random as crypto_random

class Service(object):
    SESSION_NONCE_BIT_LENGTH = 128

    def __init__(self, domain):
        self.domain = domain
        self.identities_by_subject = {}
        self.session_nonces = set()
        self.identity_by_session = {}

    def make_session_nonce(self):
        nonce = crypto_random(SESSION_NONCE_BIT_LENGTH // 8)
        self.session_nonces.add(nonce)
        return nonce

    def register_identity(self, identity):
        assert identity.subject not in self.identities_by_subject
        assert identity.domain == self.domain
        assert identity.verify()
        self.identities_by_subject[identity.subject]  = identity

    def revoke_and_replace(self, old_subject, revocation_key, new_identity):
        old_identity = self.identities_by_subject[old_subject]
        assert sha256(revocation_key) == old_identity.revocation_key_hash

        del self.identities_by_subject[old_subject]
        self.register_identity(new_identity)

    def fetch_identity_nonce(self, subject):
        return self.identities_by_subject[subject].nonce

    def session_login(self, subject, session_nonce, signed_session_nonce):
        assert session_nonce in self.session_nonces
        identity = self.identities_by_subject[subject]
        public_key = identity.build_public_key()
        assert public_key.verify(session_nonce, from_base64(signed_session_nonce))
        self.session_nonces.remove(session_nonce)
        self.identity_by_session[session_nonce] = identity

    def session_logou(self, session_nonce):
        assert session_nonce in self.identity_by_session
        del self.identity_by_session[session_nonce]