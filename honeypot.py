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


class SimpleShell:
    """Shell minimaliste -juste quelques commandes """

    def __init__(self,channel,client_ip):
        self.channel = channel
        self.client_ip = client_ip
        self.buffer = ""

    def start(self):
        """la methode lance le shell"""

        # message de bienvenue

        self.channel.send(b"Ubuntu 22.04 LTS\r\n\r\n")
        self._prompt()

        # boucle de lecture

        while True:
            try:
                char = self.channel.recv(1)
                if not char:
                    break
                
                char = char.decode('utf-8', errors='replace')
                
                # Enter = exécuter la commande
                if char in ['\r', '\n']:
                    cmd = self.buffer.strip()
                    if cmd:
                        self._execute(cmd)
                        self._log_cmd(cmd)
                    self.buffer = ""
                    self._prompt()
                
                # Backspace
                elif char == '\x7f':
                    if self.buffer:
                        self.buffer = self.buffer[:-1]
                        self.channel.send(b'\x08 \x08')
                
                # Ctrl+C
                elif char == '\x03':
                    self.channel.send(b'^C\r\n')
                    self.buffer = ""
                    self._prompt()
                
                # Ctrl+D = exit
                elif char == '\x04':
                    break
                
                # Caractère normal
                else:
                    self.buffer += char
                    self.channel.send(char.encode())
            
            except:
                break
        
        logger.info(f"Session terminée - {self.client_ip}")

        

