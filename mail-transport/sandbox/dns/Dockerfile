FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends bind9 bind9utils unbound \
    && rm -rf /var/lib/apt/lists/*
COPY start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh
EXPOSE 53/udp 53/tcp
CMD ["/usr/local/bin/start.sh"]
