FROM metasploitframework/metasploit-framework:latest

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 55553

ENTRYPOINT ["/entrypoint.sh"]
