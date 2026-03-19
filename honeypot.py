#!/usr/bin/env python3

import paramiko
import socket 
import threading
import json
import logging
import os
from datetime import datetime

# on implemente ici le logging simplifie

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger("SSH-Honeypot")

class SSHHoneypot(paramiko.ServerInterface):
    """Interface SSh Simplifiee"""

    def __init__(self,client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()

    
    def check_auth_password(self, username, password):
        """la methode capture les credentials et refuse toujours"""

        self._log({
            'type': 'auth',
            'username': username,
            'password': password
        })
        logger.warning(f"{self.client_ip} - {username}:{password}")
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        """la methode autorise les canaux de session"""

        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        """la methode autorise le pseudo-terminal"""
        return True
    
    def check_channel_shell_request(self, channel):
        """la methode autorise le shell et débloque"""
        self.event.set()
        return True
    
    def get_allowed_auths(self, username):
        """la methode accepte seulement les mots de passe"""
        return 'password'
    
    def _log(self, data):
        """la methode enregistre dans le fichier JSON"""
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'ip': self.client_ip,
            **data
        }
        
        log_file = os.getenv('LOG_FILE', '/app/logs/honeypot.log')
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        with open(log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')
