import requests
import hashlib
import time
import json

class KeyAuthException(Exception):
    pass

class api:
    def __init__(self, name, ownerid, secret, version, hash_to_check):
        self.name = name
        self.ownerid = ownerid
        self.secret = secret
        self.version = version
        self.hash_to_check = hash_to_check

        if len(self.ownerid) != 10:
            raise ValueError("OwnerID should be exactly 10 characters long.")

        self.sessionid = None
        self.initialized = False

        self.app_data = {}
        self.user_data = {}

        self.init()

    def init(self):
        self.check_hash()

        data = {
            "type": "init",
            "name": self.name,
            "ownerid": self.ownerid,
            "init_secret": self.secret,
            "version": self.version,
            "hash": self.hash_to_check,
        }

        response = self.__do_request(data)

        if response.get("success"):
            self.sessionid = response.get("sessionid")
            self.app_data = response.get("appinfo", {})
            self.initialized = True
        else:
            raise KeyAuthException(response.get("message", "Unknown error occurred during initialization."))

    def check_hash(self):
        pass

    def license(self, key):
        if not self.initialized:
            raise KeyAuthException("The application has not been initialized.")

        data = {
            "type": "license",
            "key": key,
            "sessionid": self.sessionid,
            "name": self.name,
            "ownerid": self.ownerid,
        }

        response = self.__do_request(data)

        if response.get("success"):
            self.user_data = response.get("info", {})
        else:
            raise KeyAuthException(response.get("message", "Unknown error occurred during license check."))

    def __do_request(self, data):
        url = "https://keyauth.win/api/1.2/"
        try:
            response = requests.post(url, data=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as http_err:
            raise KeyAuthException(f"HTTP error occurred: {http_err}")
        except requests.exceptions.RequestException as req_err:
            raise KeyAuthException(f"Request error occurred: {req_err}")
        except json.JSONDecodeError as json_err:
            raise KeyAuthException(f"JSON decode error: {json_err}")
