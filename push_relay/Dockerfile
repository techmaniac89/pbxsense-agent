FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock
COPY app.py .

RUN adduser --disabled-password --gecos "" pbxsense-relay
USER pbxsense-relay

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
