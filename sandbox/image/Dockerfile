# dfir-sandbox: offline analysis image for the disposable sandbox.
# Tools are baked in at BUILD time (build has network); at RUN time the sandbox
# has NO network (--network none). Nothing here needs the internet to run.
FROM python:3.12-slim

# System unpackers: 7-Zip (AES-256 zip, method 99), unrar, plus libs some
# parsers need. apt runs only during build.
RUN set -eux; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        p7zip-full libmagic1 ca-certificates; \
    rm -rf /var/lib/apt/lists/*

# Python analysis/parsing libs (read-only forensic parsing of collector output
# and raw input artifacts). PyCryptodome covers AE-2 if ever needed in-sandbox.
RUN pip install --no-cache-dir \
        python-magic \
        pycryptodomex \
        python-evtx \
        regipy \
        chardet

# non-root by default (the launcher also forces --user 65534)
RUN useradd -r -u 65534 -g nogroup sandbox 2>/dev/null || true
WORKDIR /work
ENV PYTHONDONTWRITEBYTECODE=1
# No ENTRYPOINT: the launcher runs `python3 /opt/analyze.py ...` explicitly.
LABEL org.dfir.purpose="disposable isolated forensic archive analysis (no network at runtime)"
