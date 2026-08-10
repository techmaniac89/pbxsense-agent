FROM eclipse-temurin:8-jre@sha256:058a4f63a2338710054e905f88cd50e843173124b50a921df83e77506af6fc82 AS jtapi-java

FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

WORKDIR /app

COPY --from=jtapi-java /opt/java/openjdk /opt/java/openjdk

COPY requirements.lock .
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY pbxsense_agent ./pbxsense_agent
COPY jtapi_bridge ./jtapi_bridge

RUN adduser --disabled-password --gecos "" pbxsense \
  && mkdir -p /var/lib/pbxsense-agent /var/log/pbxsense-agent \
  && chown -R pbxsense:pbxsense /var/lib/pbxsense-agent /var/log/pbxsense-agent
USER pbxsense

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os, ssl, urllib.request; port=os.environ.get('PBXSENSE_AGENT_PORT', '8765'); tls=bool(os.environ.get('PBXSENSE_AGENT_TLS_CERTFILE')); scheme='https' if tls else 'http'; context=ssl._create_unverified_context() if tls else None; urllib.request.urlopen(f'{scheme}://127.0.0.1:{port}/health', timeout=3, context=context).read()"

CMD ["python", "-m", "pbxsense_agent.server"]
