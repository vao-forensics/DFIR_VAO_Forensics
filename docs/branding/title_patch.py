# -*- coding: utf-8 -*-
# Remove the hardcoded " • Open WebUI" browser-tab-title suffix from built JS.
# NOTE: these JS files are content-hashed + long-cached by the browser -> a hard refresh
# (Ctrl+Shift+R) is needed once to see it. Safe: " • Open WebUI" (bullet-prefixed) is the
# title template only; "Open WebUI Community" links lack the " • " prefix so stay intact.
import os
base = "/app/build/_app/immutable"
needle = " • Open WebUI"   # space + bullet(U+2022) + space + Open WebUI
n_files = 0
for dp,_,files in os.walk(base):
    for fn in files:
        if not fn.endswith('.js'): continue
        p = os.path.join(dp,fn)
        t = open(p, encoding='utf-8', errors='ignore').read()
        if needle in t:
            open(p+'.bak_title','w',encoding='utf-8').write(t)
            open(p,'w',encoding='utf-8').write(t.replace(needle, ''))
            n_files += 1
print("patched tab-title in %d JS file(s)" % n_files)
