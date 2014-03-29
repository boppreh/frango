import sys
sys.path.append('../simplecrypto')

from simplecrypto.hashes import sha256
from collections import namedtuple

class Identity(namedtuple('Identity', 'subject domain nounce public_key revocation_key_hash signature')):
	"""
	Auto-signed document:

	Subject -> hash(master-key + domain)
	Domain -> from server
	Nounce -> random from user
	Public Key -> random(master-key + domain + nounce)
	hash(hash(nounce + domain + master key))
	"""
	pass