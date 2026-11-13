SHELL := /bin/bash
SVC   := case-maintainer
APP   := services/case_maintainer/app.py

.PHONY: help test lint restart logs status backup

help:
	@echo "make test     — run pytest (no DB needed)"
	@echo "make lint     — check syntax"
	@echo "make restart  — restart $(SVC) container"
	@echo "make logs     — tail container logs"
	@echo "make status   — show all container statuses"
	@echo "make backup   — snapshot code to backups/code_snapshots/"

test:
	python3 -m pytest tests/ -v --tb=short

lint:
	python3 -m py_compile services/case_maintainer/app.py && \
	python3 -m py_compile services/case_maintainer/core/config.py && \
	echo "Syntax OK"

restart:
	docker compose up -d $(SVC)

logs:
	docker logs $(SVC) -f --tail 50

status:
	docker compose ps

backup:
	@STAMP=$$(date +%Y%m%d_%H%M%S) && \
	tar -czf backups/code_snapshots/case_maintainer_$$STAMP.tar.gz \
	    services/case_maintainer/app.py \
	    services/case_maintainer/core/ \
	    services/case_maintainer/Dockerfile \
	    services/case_maintainer/requirements.txt \
	    docker-compose.yml && \
	echo "Backup: backups/code_snapshots/case_maintainer_$$STAMP.tar.gz" && \
	ls -lh backups/code_snapshots/ | tail -5
