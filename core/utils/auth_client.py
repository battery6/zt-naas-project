###################################################################
#    Auth Client                                                  #
#        Communicates with authentication and attribute server    #
###################################################################

import requests

class AuthClient:
    def __init__(self, logger):
        self.logger = logger

    def is_authenticated(self, ip):
        """ Check if entity is authenticated

            Args:
                ip (string): entity ip
        """
        try:
           response = requests.get(
               "https://127.0.0.1:5000/authenticated", 
               timeout=1, verify=False
           )
           authenticated_hosts = response.json()
           return ip in authenticated_hosts

        except Exception as e:
           self.logger.warning("Authentication service error: %s", e)
           return False

    def get_live_attributes(self, ip):
        """ Gets current registrered entity attributes from server

            Args:
                ip (string): entity ip
        """
        try:
            response = requests.get(
                f"https://127.0.0.1:5000/attributes/{ip}",
                timeout=1,
                verify=False
            )
            if response.status_code != 200:
                return {}

            return response.json()

        except Exception as e:
            self.logger.warning("Attribute service error: %s", e)
            return {}


    def update_host_attributes(self, ip, attributes):
        """ Updates entity attributes on server

            Args:
                ip (string): entity ip
                attributes (dict): new entity attributes
        """
        try:
            response = requests.post(
                f"https://127.0.0.1:5000/attributes/{ip}",
                json=attributes,
                timeout=1,
                verify=False
            )

            if response.status_code != 200:
                return False, f"Attribute service returned {response.status_code}", None

            updated = response.json()

            self.logger.info(
                "UPDATED LIVE ATTRIBUTES ip=%s attributes=%s",
                ip, updated
            )

            return True, f"Updated live attributes for {ip}", updated

        except Exception as e:
            self.logger.warning("Attribute service update error: %s", e)
            return False, str(e), None
