.PHONY: help install run test lint docker up down clean seed

help:
	@echo "ATT&CK Coverage Dashboard v2 - common operations"
	@echo ""
	@echo "  make install   Install runtime + dev requirements"
	@echo "  make run       Run Streamlit locally"
	@echo "  make test      Run pytest suite with coverage"
	@echo "  make lint      Ruff lint"
	@echo "  make docker    Build container image"
	@echo "  make up        docker compose up -d"
	@echo "  make down      docker compose down"
	@echo "  make seed      Import the sample Sigma rules"
	@echo "  make clean     Remove caches and the local DB"

install:
	pip install -r requirements-dev.txt

run:
	streamlit run app/main.py

test:
	pytest tests/ -v --cov=app --cov-report=term-missing

lint:
	ruff check app/ tests/

docker:
	docker build -t attack-dashboard:latest .

up:
	docker compose up -d
	@echo ""
	@echo "Dashboard: http://localhost:8501"

down:
	docker compose down

seed:
	python -c "from app.db import RuleStore; from app.importers import import_sigma_directory; \
	store = RuleStore('data/dashboard.db'); \
	r = import_sigma_directory('data/sample_rules', store); \
	print(f'Imported {r[\"imported\"]} sample rules')"

clean:
	rm -rf .pytest_cache __pycache__ */__pycache__ */*/__pycache__
	rm -rf .coverage htmlcov
	rm -f data/dashboard.db
