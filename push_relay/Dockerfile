FROM python:3.14-slim@sha256:a7fb1e634c4a578f9e0bd6327f11a3cde11b7a9395f48e24360c0988bcc5c2bc

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY app.py .

RUN adduser --disabled-password --gecos "" pbxsense-relay
USER pbxsense-relay

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
