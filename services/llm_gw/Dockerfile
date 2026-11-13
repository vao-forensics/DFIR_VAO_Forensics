FROM python:3.12-slim
RUN pip install --no-cache-dir "aiohttp==3.12.15" "psycopg[binary]==3.2.10"
COPY gateway.py keys.py /srv/
WORKDIR /srv
CMD ["python", "-u", "/srv/gateway.py"]
