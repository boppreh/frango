import os
import requests
import json
from structures import User, Identity

class Client(object):
    IDENTITY_SERVICE_FORMAT = 'http://{}:8080/identity/{}'

    def __init__(self, backup_path):
        if os.path.isfile(backup_path):
            with open(backup_path, 'rb') as f:
                master_key = f.read()
                self.user = User(master_key)
        else:
            with open(backup_path, 'wb') as f:
                self.user = User()
                f.write(self.user.master_key)

        self.identities_by_domain = {}

    def _get_service_url(self, domain, subject):
        return Client.IDENTITY_SERVICE_FORMAT.format(domain, subject)
            
    def login(self, domain):
        subject = self.user.get_subject(domain)
        response = requests.get(self._get_service_url(domain, subject))

        if response.ok:
            self._load_identity_from_response(response)
        else:
            self.register(domain)
            
        return self._authenticate(domain)

    def _load_identity_from_response(self, domain, response):
        identity_dict = json.loads(response.text)
        identity = Identity(**identity_dict)

    def register(self, domain):
        identity = self.user.build_identity(domain)
        subject = identity.subject
        response = requests.post(self._get_service_url(domain, subject), data=identity)
        assert response.ok
        
    def authenticate(self, domain):
        identity = self.identities_by_domain[domain]
        self._get_service_url(domain, identity.subject)