# test t1_sources_bloom_check: the bloom verification really loads the filter and measures its false-positive rate
import os, sys
sys.path.insert(0, "/srv/dfir/tools/sources"); import dfir_sources as d
src = [s for s in d.manifest()["sources"] if s["id"] == "circl_hashlookup_bloom"][0]
up = d.resolve(src); f = os.path.join(d.dest_dir(), src["file"])
r = d.verify(src, up, f, os.path.getsize(f), {})
print(r); sys.exit(0 if all(c["ok"] for c in r) else 1)
