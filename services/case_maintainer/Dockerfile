FROM python:3.12-alpine
# reportlab font support; libstdc++/libgcc are needed by pymupdf's native wheel
RUN apk add --no-cache fontconfig ttf-dejavu libstdc++ libgcc
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# impacket, isolated in /opt/impacket so it never shadows the app's own deps.
# Used by analysis/ntlm_extract.py (offline NTLM hashes from SAM+SYSTEM), which is
# invoked as a subprocess with PYTHONPATH=/opt/impacket. Baked into the image on
# 2026-08-01 - it used to live only in the container writable layer and was lost on
# every recreate. Offline fallback wheels: /home/dfir-bot/dfir/vendor/impwheels.
RUN pip install --no-cache-dir --target=/opt/impacket --no-deps       impacket==0.13.1 pycryptodomex pyasn1 pyasn1_modules six       charset_normalizer ldap3 dnspython pyOpenSSL
COPY app.py .
COPY core/ core/
COPY analysis/ analysis/
EXPOSE 8787
CMD ["gunicorn","--bind","0.0.0.0:8787","--workers","1","--timeout","1200","--keep-alive","5","app:app"]
