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

