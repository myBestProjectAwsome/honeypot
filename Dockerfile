FROM python:3.11-slim

WORKDIR /app

# Dépendances
RUN pip install --no-cache-dir paramiko==3.4.0

# Code
COPY honeypot.py .

# Logs
RUN mkdir -p /app/logs

# Port
EXPOSE 2222

# Démarrage
CMD ["python3", "-u", "honeypot.py"]
