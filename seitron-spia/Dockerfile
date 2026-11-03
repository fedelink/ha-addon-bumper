FROM python:3.12-alpine
RUN apk add --no-cache openssl
COPY spia.py /spia.py
CMD ["sh", "-c", "openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj /CN=smartfan.it -keyout /tmp/key.pem -out /tmp/cert.pem 2>/dev/null && exec python3 -u /spia.py"]
