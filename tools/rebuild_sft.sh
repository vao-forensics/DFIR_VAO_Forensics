#!/bin/sh
# Rebuild the expanded SFT training dataset (option Б) as cases accumulate. Runs the builder
# inside case-maintainer (has PG access), then copies the JSONL out to the finetune folder.
docker cp /srv/dfir/tools/build_sft.py case-maintainer:/tmp/build_sft.py 2>/dev/null
docker exec case-maintainer python3 /tmp/build_sft.py > /tmp/sft_rebuild.log 2>&1
docker cp case-maintainer:/tmp/dfir_sft_expanded.jsonl /srv/dfir/cases/_finetune/dfir_sft_expanded.jsonl 2>/dev/null
echo "$(date '+%Y-%m-%d %H:%M') rebuild: $(tail -1 /tmp/sft_rebuild.log)" >> /srv/dfir/cases/_finetune/rebuild_history.log
