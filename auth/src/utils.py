from typing import Type, TypeVar

import pydantic
from authlib.integrations.flask_client import OAuth
from exceptions import RequestValidationError
from flask import current_app
from passlib import pwd
from pydantic import BaseModel, ValidationError

BM = TypeVar("BM", bound=BaseModel)


def parse_obj_raise(model_type: Type[BM], data: dict) -> BM:
    try:
        user_data = pydantic.parse_obj_as(model_type, data)
        return user_data
    except ValidationError as e:
        raise RequestValidationError(e)


def generate_random_password(length=12) -> str:
    return pwd.genword(length=length)


def get_oauth() -> OAuth:
    # with current_app.request_context():
    return current_app.extensions["authlib.integrations.flask_client"]
