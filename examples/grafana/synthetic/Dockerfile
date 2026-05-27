FROM python:3.12-alpine

WORKDIR /app

COPY produce.py /app/produce.py

# Runs as root in the demo because it shares a Docker volume with Alloy
# and writes to /var/log/pamsignal-demo. Demo only; never deploy this
# image to a host.

ENTRYPOINT ["python", "/app/produce.py"]
