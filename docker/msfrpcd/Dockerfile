FROM metasploitframework/metasploit-framework:latest

USER root

RUN (apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*) 2>/dev/null || \
    (apk add --no-cache curl) 2>/dev/null || true

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 55553

ENTRYPOINT ["/entrypoint.sh"]
