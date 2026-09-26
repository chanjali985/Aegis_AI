.PHONY: install test demo serve benchmark docker

install:
	pip install -e ".[dev]"

test:
	pytest -q

demo:
	aegis demo --scenario payment-db-timeout

serve:
	aegis serve --port 8000

benchmark:
	aegis benchmark --n 100

docker:
	docker compose up --build
