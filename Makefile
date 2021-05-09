.PHONY = help setup test dev clean
.DEFAULT_GOAL := help

build:
	docker-compose build

run:
	docker-compose build
	docker-compose down
	docker-compose up -d --scale etl=0
	sleep 3
	docker-compose exec auth_api python manage.py cleanup
	docker-compose exec auth_api python manage.py init_db
	docker-compose exec auth_api python manage.py create_adminuser admin@example.com testpass
	docker-compose logs -f

sweep:
	isort auth/src/ movie_api/src
	black auth/src movie_api/src
	flake8 auth/src movie_api/src

run_etl:
	bash -c "curl -XPUT http://localhost:9200/movies -H 'Content-Type: application/json' -d @movie_api/schemas/es.movies.schema.json; \
  	curl -XPUT http://localhost:9200/persons -H 'Content-Type: application/json' -d @movie_api/schemas/es.persons.schema.json; \
    curl -XPUT http://localhost:9200/genres -H 'Content-Type: application/json' -d @movie_api/schemas/es.genres.schema.json"

	docker-compose up etl

clean:
	docker-compose down -v --remove-orphans

rebuild:
	docker-compose build movie_api auth_api

tests:
	bash -c "cd movie_api && ./run.sh tests && cd -"

help:
	@echo "available commands: help, dev, setup_demo, sweep, run, clean"