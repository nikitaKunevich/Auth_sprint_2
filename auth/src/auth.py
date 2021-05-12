import logging
from functools import wraps
from typing import Union

import permissions
import token_store
from api.models import RoleIn, RoleOut
from exceptions import AlreadyExistsError, PasswordAuthenticationError, TokenError
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    current_user,
    decode_token,
)
from passlib.hash import argon2
from storage import db
from storage.db_models import LoginRecord, Role, ThirdPartyAccount, User
from utils import generate_random_password
from werkzeug.exceptions import Forbidden, NotFound
from werkzeug.useragents import UserAgent

logger = logging.getLogger(__name__)


def verify_password(user: User, password: str):
    return argon2.verify(password, user.hashed_password)


def hash_password(password: str) -> str:
    return argon2.hash(password)


def create_user(email: str, password: str, admin: bool = False) -> User:
    # checking if user already exists
    user_exists = User.get_user_universal(email) is not None
    if user_exists:
        raise AlreadyExistsError(f"User with email: {email} already exists")

    hashed_pass = hash_password(password)
    user = User(email=email, hashed_password=hashed_pass)
    if admin:
        admin_role = db.session.query(Role).filter_by(name="admin").one_or_none()
        assert admin_role, "No admin role found"
        user.roles = [admin_role]
    db.session.add(user)
    db.session.commit()
    return user


def create_user_from_third_party(third_party_account_id: str, user_info: dict) -> User:
    hashed_pass = hash_password(generate_random_password())
    email = user_info["email"] if user_info["email_verified"] else None
    if email:
        user_exists = User.get_user_universal(email) is not None
        if user_exists:
            raise AlreadyExistsError(f"User with email: {email} already exists")
    account = ThirdPartyAccount(
        id=third_party_account_id,
        third_party_name=user_info["iss"],
        user_info=user_info,
    )
    user = User(
        email=email,
        hashed_password=hashed_pass,
        should_change_password=True,
        third_party_accounts=[account],
    )
    db.session.add(user)
    db.session.commit()
    return user


def authenticate_with_email(email: str, password: str) -> User:
    user = User.get_user_universal(email=email)
    if not user:
        logger.debug(f"user with email {email} not found")
        raise PasswordAuthenticationError
    if not verify_password(user, password):
        logger.debug("password is not valid")
        raise PasswordAuthenticationError
    return user


def issue_tokens(user: User, user_agent: UserAgent, ip: str) -> tuple[str, str]:
    device_id = token_store.user_agent_to_device_id(user_agent)
    access_token = create_access_token(user, additional_claims={"device": device_id})
    refresh_token = create_refresh_token(user, additional_claims={"device": device_id})
    token_data = decode_token(refresh_token)
    token_store.replace_refresh_token(
        token_data["jti"], token_data["sub"], token_data["device"]
    )

    # save login in history
    browser_string = user_agent.browser
    if user_agent.version:
        browser_string = f"{browser_string}-{user_agent.version}"
    record = LoginRecord(
        user_id=user.id,
        ip=ip,
        user_agent=user_agent.string,
        platform=user_agent.platform,
        browser=browser_string,
    )
    db.session.add(record)
    db.session.commit()

    return access_token, refresh_token


def refresh_tokens(user: User, token_data: dict) -> tuple[str, str]:
    logger.debug(f"refresh_tokens: {token_data=}, {user=}")

    device_id = token_data["device"]

    access_token = create_access_token(user, additional_claims={"device": device_id})
    refresh_token = create_refresh_token(user, additional_claims={"device": device_id})
    new_token_jti = decode_token(refresh_token)["jti"]

    token_store.replace_refresh_token(
        new_token_jti, token_data["sub"], token_data["device"]
    )

    return access_token, refresh_token


def logout_all_user_devices(user: User):
    token_store.remove_all_user_refresh_tokens(user.id)


def remove_device_token(user: User, user_agent: UserAgent):
    device_id = token_store.user_agent_to_device_id(user_agent)
    token_store.remove_refresh_token(user.id, device_id)


def create_role(role_data: RoleIn) -> RoleOut:
    role = Role(**role_data.dict())
    db.session.add(role)
    db.session.commit()
    return RoleOut(id=role.id, name=role.name, desription=role.description)


def delete_role(role_id: int):
    role = db.session.query(Role).filter_by(id=role_id).one_or_none()
    if not role:
        return

    db.session.delete(role)
    db.session.commit()


def require_permissions(permission_list: Union[str, list]):
    if isinstance(permission_list, str):
        permission_list = [permission_list]

    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            user: User = current_user
            if not user:
                raise TokenError("You should provide valid access_token", "")
            required_permissions_set = set(permission_list)
            user_permissions_set = {permission for permission in user.permissions}
            if not required_permissions_set.issubset(user_permissions_set):
                raise Forbidden("User doesn't have access to the resource")
            return fn(*args, **kwargs)

        return decorator

    return wrapper


def add_role_to_user(role_name, user_id):
    role = Role.get(role_name)

    user = User.get_by_id(user_id)
    if not user:
        raise NotFound(f"User with id {user_id} is not found")
    user.roles.append(role)
    db.session.add(user)
    db.session.commit()


def remove_role_from_user(role_name, user_id):
    role = Role.get(role_name)
    user = User.get_by_id(user_id)
    if not user:
        raise NotFound(f"User with id {user_id} is not found")
    user.roles.remove(role)
    db.session.add(user)
    db.session.commit()


def add_permission_to_role(role_name, permission_name):
    role = Role.get(role_name)
    if permission_name not in permissions.Permissions.__members__:
        raise NotFound(f"Permission with name {permission_name} is not found")
    role.permissions.append(permission_name)
    db.session.add(role)
    db.session.commit()


def remove_permission_from_role(role_name, permission_name):
    role = Role.get(role_name)
    if permission_name not in permissions.Permissions.__members__:
        raise NotFound(f"Permission with name {permission_name} is not found")
    role.permissions.remove(permission_name)
    db.session.add(role)
    db.session.commit()
