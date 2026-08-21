FROM eclipse-temurin:8-jre@sha256:058a4f63a2338710054e905f88cd50e843173124b50a921df83e77506af6fc82 AS jtapi-java

FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

WORKDIR /app

COPY --from=jtapi-java /opt/java/openjdk /opt/java/openjdk

COPY requirements.lock .
RUN apt-get update \
  && apt-get install -y --no-install-recommends curl \
  && rm -rf /var/lib/apt/lists/* \
  && pip install --no-cache-dir --require-hashes -r requirements.lock

COPY pbxsense_agent ./pbxsense_agent
COPY jtapi_bridge ./jtapi_bridge
COPY docker/healthcheck.sh /usr/local/bin/pbxsense-healthcheck

RUN adduser --disabled-password --gecos "" pbxsense \
  && mkdir -p /var/lib/pbxsense-agent /var/log/pbxsense-agent \
  && chmod 0755 /usr/local/bin/pbxsense-healthcheck \
  && chown -R pbxsense:pbxsense /var/lib/pbxsense-agent /var/log/pbxsense-agent
USER pbxsense

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/pbxsense-healthcheck"]

CMD ["python", "-m", "pbxsense_agent.server"]
