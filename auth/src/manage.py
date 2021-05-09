#!/usr/bin/env python

"""This file sets up a command line manager.

Use "python manage.py" for a list of available commands.
Use "python manage.py runserver" to start the development web server on localhost:5000.
Use "python manage.py runserver --help" for a list of runserver options.
"""

import auth
from app import create_app
from flask_script import Manager
from openapi_spec import get_api_spec
from sqlalchemy_utils import create_database, database_exists
from storage import db
from storage.db import Base, engine

manager = Manager(create_app)


@manager.command
def init_db():
    if not database_exists(engine.url):
        print(f"creating database: {engine.url}")
        create_database(engine.url)
    db.init_db()
    print("Database has been initialized.")


@manager.command
def create_user(name, password):
    auth.create_user(name, password)


@manager.command
def create_adminuser(name, password):
    auth.create_user(name, password, True)


@manager.command
def cleanup():
    if database_exists(engine.url):
        Base.metadata.drop_all(engine)


@manager.command
def showapi():
    print(get_api_spec().to_yaml())


if __name__ == "__main__":
    # python manage.py                      # shows available commands
    # python manage.py runserver --help     # shows available runserver options
    manager.run()
