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

    def _prompt(self):
        """la methode affiche le prompt"""

        self.channel.send(b"root@server:~# ")

    

    def _execute(self, cmd):
        """la methode simule une commande"""
        parts = cmd.split()
        if not parts:
            return
        
        command = parts[0]
        
        # des commandes basiques
        responses = {
            'ls': 'Documents  Downloads  .ssh',
            'pwd': '/root',
            'whoami': 'root',
            'uname': 'Linux server 5.15.0-52-generic x86_64',
            'id': 'uid=0(root) gid=0(root) groups=0(root)',
        }
        
        if command in responses:
            self.channel.send((responses[command] + '\r\n').encode())
        elif command in ['wget', 'curl']:
            self.channel.send(b'Connection refused\r\n')
        elif command == 'exit':
            self.channel.send(b'logout\r\n')
            self.channel.close()
        else:
            self.channel.send(f"bash: {command}: command not found\r\n".encode())



    def _log_cmd(self, cmd):
        """la methode log une commande"""
        entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'ip': self.client_ip,
            'type': 'command',
            'command': cmd
        }
        
        log_file = os.getenv('LOG_FILE', '/app/logs/honeypot.log')
        with open(log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    

def handle_client(client_socket, client_address):
    """la fonction gere une connexion client"""
    client_ip = client_address[0]
    
    try:
        # Setup SSH
        transport = paramiko.Transport(client_socket)
        host_key = paramiko.RSAKey.generate(2048)
        transport.add_server_key(host_key)
        
        server = SSHHoneypot(client_ip)
        transport.start_server(server=server)
        
        # Attendre un canal
        channel = transport.accept(20)
        if channel is None:
            return
        
        # Démarrer le shell
        server.event.wait()
        shell = SimpleShell(channel, client_ip)
        shell.start()
    
    except Exception as e:
        logger.error(f"Erreur - {client_ip}: {e}")
    finally:
        try:
            transport.close()
        except:
            pass


def start_honeypot(host='0.0.0.0', port=2222):
    """la fonction demarre le honeypot"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((host, port))
        server_socket.listen(100)
        
        logger.info(f"🍯 Honeypot démarré sur {host}:{port}")
        logger.info(f"📝 Logs: {os.getenv('LOG_FILE', '/app/logs/honeypot.log')}")
        
        while True:
            client_socket, client_address = server_socket.accept()
            logger.info(f"Connexion depuis {client_address[0]}")
            
            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()
    
    except KeyboardInterrupt:
        logger.info("\nArrêt du honeypot")
    finally:
        server_socket.close()


if __name__ == '__main__':
    HOST = os.getenv('HONEYPOT_HOST', '0.0.0.0')
    PORT = int(os.getenv('HONEYPOT_PORT', '2222'))
    start_honeypot(HOST, PORT)


