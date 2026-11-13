FROM python:3.12-slim
# стартовий інструментарій DFIR + можливість ставити ще (apt/pip доступні)
RUN apt-get update && apt-get install -y --no-install-recommends     file unzip p7zip-full sqlite3 curl git xxd jq ripgrep less nano ca-certificates build-essential     && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir pandas python-dateutil regipy python-evtx yara-python oletools pefile 2>/dev/null || pip install --no-cache-dir pandas python-dateutil
WORKDIR /home/user
CMD ["sleep", "infinity"]
