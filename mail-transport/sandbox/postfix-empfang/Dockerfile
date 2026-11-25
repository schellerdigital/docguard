FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        postfix age python3 \
    && rm -rf /var/lib/apt/lists/*

COPY docguard_unwrap.py /usr/local/bin/docguard_unwrap.py
RUN chmod +x /usr/local/bin/docguard_unwrap.py \
    && mkdir -p /var/log/docguard && chown nobody /var/log/docguard && touch /var/log/mail.log

EXPOSE 25
CMD ["/bin/sh", "-c", "service postfix start && tail -F /var/log/mail.log /var/log/docguard/unwrap.log"]
