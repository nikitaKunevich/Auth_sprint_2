# import auth
# import click
# from flask.cli import AppGroup, with_appcontext
# from openapi_spec import get_api_spec
# from sqlalchemy_utils import create_database, database_exists
# from storage import db
# from storage.db import Base, engine
# # from flask_script import Command, mana
#
#
# class InitDbCommand(Command):
#     """Initialize the database."""
#
#     def run(self):
#         if not database_exists(engine.url):
#             print(f"creating database: {engine.url}")
#             create_database(engine.url)
#         db.init_db()
#         print("Database has been initialized.")
#
#
# # cli = AppGroup()
#
# #
# # @cli.command("initdb")
# # @with_appcontext
# # def initdb():
# #     if not database_exists(engine.url):
# #         print(f"creating database: {engine.url}")
# #         create_database(engine.url)
# #     db.init_db()
#
# class CreateUserCommand(Command):
#     """Initialize the database."""
#
#     def run(self):
#         if not database_exists(engine.url):
#             print(f"creating database: {engine.url}")
#             create_database(engine.url)
#         db.init_db()
#         print("Database has been initialized.")
#
#
# @cli.command("create-user")
# @click.argument("name")
# @click.argument("password")
# @with_appcontext
# def create_user(name, password):
#     auth.create_user(name, password)
#
# @cli.command("create-user")
# @click.argument("name")
# @click.argument("password")
# @with_appcontext
# def create_user(name, password):
#     auth.create_user(name, password)
#
#
# @cli.command("create-adminuser")
# @click.argument("name")
# @click.argument("password")
# @with_appcontext
# def create_adminuser(name, password):
#     auth.create_user(name, password, True)
#
#
# @cli.command("cleanup")
# @with_appcontext
# def cleanup():
#     if database_exists(engine.url):
#         Base.metadata.drop_all(engine)
#
#
# @cli.command("showapi")
# @with_appcontext
# def showapi():
#     print(get_api_spec().to_yaml())
