FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        postfix age python3 python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages --no-cache-dir dnspython

COPY docguard_filter.py /usr/local/bin/docguard_filter.py
RUN chmod +x /usr/local/bin/docguard_filter.py \
    && mkdir -p /var/log/docguard && chown nobody /var/log/docguard && touch /var/log/mail.log

EXPOSE 25
CMD ["/bin/sh", "-c", "service postfix start && tail -F /var/log/mail.log /var/log/docguard/filter.log"]
