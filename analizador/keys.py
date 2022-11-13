import requests
from requests.auth import HTTPBasicAuth
from ipaddress import ip_address
import json

def keyReturn():
        secrets_filename = 'keys.json'
        api_keys = {}
        with open(secrets_filename, 'r') as f:
                api_keys = json.loads(f.read())
                return api_keys
                       