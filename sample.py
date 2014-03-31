from service import Service
from user import User

service = Service('example.org')
user = User()

# User backs up master key.
master_key_backup = user.master_key

# User registers with service.
identity = user.build_identity('example.org')
service.register_identity(identity)

# User accesses service webpage. This page contains a login QR code.
nonce = service.make_session_nonce()

# User reads QR code with cellphone.
# Signs the nonce...
signed_nonce = user.sign(nonce, 'example.org')
# And sends this info back to the service.
service.session_login(identity.subject, nonce, signed_nonce)

# Server now nows which user is behind that session. User is logged in.
# Client and server can talk with TLS, using the server's cert and the user's
# public key from the identity.

# User logouts, releasing the session.
# This must be done in an authenticated channel to avoid DOS.
service.session_logout(nonce)

# The user promptly loses his phone.
user = None

# Thankfully we have the backup.
new_user = User(master_key_backup)

# Problem: the identity created was not backed up.
# Solution: ask the server.
subject = new_user.get_subject('example.org')
identity_nonce = service.fetch_identity_nonce(subject)

# We could reload the identity and continue using the service as normal:
# user.load_identity('example.org', nonce)
# But whoever got the phone now has our keys, so we better revoke them.
revocation_key = new_user.revoke('example.org', identity_nonce)
new_identity = new_user.build_identity('example.org')
service.revoke(subject, revocation_key, new_identity)

# We now have a brand new identity to use:
nonce = service.make_session_nonce()
signed_nonce = new_user.sign(nonce, 'example.org')
service.session_login(new_identity.subject, nonce, signed_nonce)
service.session_logout(nonce)
