# -*- coding: utf-8 -*-
# White-label: /api/config (runtime, cache-proof) returns name="VAO", version="".
# Patches backend env.py (drops the " (Open WebUI)" append, name=VAO, local favicon) and
# main.py (blank version). In the image layer -> survives RESTART (not recreate; re-apply
# script kept). docker restart open-webui afterwards to reload the backend.
import io, shutil
E = "/app/backend/open_webui/env.py"
M = "/app/backend/open_webui/main.py"
shutil.copy(E, E + ".bak_vao"); shutil.copy(M, M + ".bak_vao")

s = io.open(E, encoding="utf-8").read()
old = ("WEBUI_NAME = os.getenv('WEBUI_NAME', 'Open WebUI')\n"
       "if WEBUI_NAME != 'Open WebUI':\n"
       "    WEBUI_NAME += ' (Open WebUI)'")
assert s.count(old) == 1, "env name-block anchor=%d" % s.count(old)
s = s.replace(old, "WEBUI_NAME = 'VAO'", 1)
fav = "WEBUI_FAVICON_URL = 'https://openwebui.com/favicon.png'"
if s.count(fav) == 1:
    s = s.replace(fav, "WEBUI_FAVICON_URL = '/static/favicon.png'", 1)
io.open(E, "w", encoding="utf-8").write(s)

t = io.open(M, encoding="utf-8").read()
n = t.count("'version': VERSION,")
t = t.replace("'version': VERSION,", "'version': '',")
io.open(M, "w", encoding="utf-8").write(t)
print("env.py: name=VAO, favicon=local | main.py: version blanked x%d" % n)
