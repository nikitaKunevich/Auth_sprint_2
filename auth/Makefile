.PHONY = help setup test dev clean
.DEFAULT_GOAL := help

env ?= compose

dev_cleanup:
	docker rm -f $$(docker ps -aq) || true

dev_setup:
	docker run -d --rm -p 6379:6379 redis:6-alpine
	docker run -d --rm -p 5432:5432 postgres:12.1

setup_demo:
	bash -c 'set -ax; source deploys/local.env; set +ax;\
	    cd src;\
		python manage.py cleanup;\
		python manage.py init_db;\
		python manage.py create_adminuser admin@example.com	testpass;\
		cd -;'

dev:
	make dev_cleanup
	make dev_setup
	sleep 3
	make setup_demo
	bash -c 'set -ax; source deploys/local.env; set +ax;\
		PYTHONPATH=src FLASK_APP="src/app.py:create_app()" flask run --host=$${HOST} --port=$${PORT}'

build:
	ENVFILE=local docker-compose build

run:
	ENVFILE=$(env) docker-compose down
	ENVFILE=$(env) docker-compose up -d
	sleep 3
	docker exec auth_sprint_1_auth_api_1 python manage.py cleanup
	docker exec auth_sprint_1_auth_api_1 python manage.py init_db
	docker-compose logs -f
sweep:
	isort auth_api
	black auth_api
	flake8 auth_api

clean:
	ENVFILE=$(env) docker-compose down -v --remove-orphans

help:
	@echo "available commands: help, dev, setup_demo, sweep, run, clean"

showapi:
	@bash -c 'set -a; source deploys/local.env; set +a; FLASK_APP="auth_api/app.py:create_app()" flask showapi'