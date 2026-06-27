FROM python:3.12-slim

WORKDIR /app

COPY proxy_stub/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY proxy_stub/ .

CMD ["python", "-u", "server.py"]