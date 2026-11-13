# test t1_sources_rollback: a corrupted download must be refused and leave the installed files untouched
import hashlib, os, sys
sys.path.insert(0, "/srv/dfir/tools/sources"); import dfir_sources as d
src = [s for s in d.manifest()["sources"] if s["id"] == "vanilla_windows_reference"][0]
f = os.path.join(d.dest_dir(), src["file"]); o = os.path.join(d.dest_dir(), src["output"])
sha = lambda p: hashlib.sha256(open(p, "rb").read()).hexdigest()
before = (sha(f), sha(o))
def bad_download(url, dest):
    open(dest, "wb").write(b"not a 7z" * 1000); return hashlib.sha256(b"x").hexdigest(), os.path.getsize(dest)
d.download = bad_download
ok = d.update_one(src, force=True)
after = (sha(f), sha(o))
last = open(d.PROV).readlines()[-1]
print("update_ok=%s files_unchanged=%s staging_gone=%s outcome=%s" % (ok, before == after,
      not os.path.exists(os.path.join(d.dest_dir(), ".staging")), '"verify_failed"' in last))
sys.exit(0 if (not ok and before == after and '"verify_failed"' in last) else 1)
