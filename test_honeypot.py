#!/usr/bin/env python3


import unittest
import paramiko
import socket
import time
import threading
import json
import os
import tempfile
from honeypot import SSHHoneypot,SimpleShell,start_honeypot

class TestSSHHoneypot(unittest.TestCase):
    """classe qui teste la classe SSHHoneypot"""

    def setUp(self):
        """la methode prepare chaque teste"""
        self.client_ip = "203.0.113.42"
        self.honeypot = SSHHoneypot(self.client_ip)
        
        # Créer un fichier log temporaire
        self.temp_log = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log')
        self.temp_log.close()
        os.environ['LOG_FILE'] = self.temp_log.name

    def tearDown(self):
        """la methode nettoie apres chaque tests"""
        if os.path.exists(self.temp_log.name):
            os.remove(self.temp_log.name)


    def test_init(self):
        """la methode verifie linitialisation"""
        self.assertEqual(self.honeypot.client_ip, "203.0.113.42")
        self.assertFalse(self.honeypot.event.is_set())
