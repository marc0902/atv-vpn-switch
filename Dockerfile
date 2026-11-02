FROM alpine:3.22

# wg (ohne wg-quick), ip, iptables (nft + legacy), conntrack, Python, Zeitzonen
RUN apk add --no-cache \
        python3 \
        tzdata \
        wireguard-tools-wg \
        iproute2 \
        iptables \
        iptables-legacy \
        conntrack-tools \
    && wg --version \
    && iptables-nft --version \
    && iptables-legacy --version \
    && conntrack --version

ENV PYTHONPATH=/app \
    PYTHONUNBUFFERED=1 \
    TZ=Europe/Berlin \
    CONFIG_DIR=/config \
    WEB_PORT=8099

COPY src/atvvpn /app/atvvpn

VOLUME ["/config"]
EXPOSE 8099

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python3 -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('WEB_PORT','8099'), timeout=4)" || exit 1

STOPSIGNAL SIGTERM
CMD ["python3", "-m", "atvvpn"]
