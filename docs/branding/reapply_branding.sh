#!/bin/bash
# Re-apply VAO white-label to open-webui after a container RECREATE (changes live in the
# image layer survive restart/reboot but NOT docker rm+run). Run: bash reapply_branding.sh
BR=/home/dfir-bot/dfir/branding
cpx(){ docker cp "$BR/vao/$1" "open-webui:$2"; }
cpx logo.png /app/build/static/logo.png
cpx splash.png /app/build/static/splash.png
cpx splash-dark.png /app/build/static/splash-dark.png
cpx favicon.png /app/build/favicon.png
cpx favicon.png /app/build/static/favicon.png
cpx favicon-96x96.png /app/build/static/favicon-96x96.png
cpx favicon-dark.png /app/build/static/favicon-dark.png
cpx apple-touch-icon.png /app/build/static/apple-touch-icon.png
cpx wam192.png /app/build/static/web-app-manifest-192x192.png
cpx wam512.png /app/build/static/web-app-manifest-512x512.png
cpx favicon.ico /app/build/static/favicon.ico
docker cp "$BR/webui_brand.py" open-webui:/tmp/webui_brand.py && docker exec open-webui python3 /tmp/webui_brand.py
docker cp "$BR/title_patch.py" open-webui:/tmp/title_patch.py && docker exec open-webui python3 /tmp/title_patch.py
docker restart open-webui
echo "VAO branding re-applied"
