import logging

import auth
from api.models import (
    RoleIn,
    TokenGrantOut,
    TokenInPassword,
    UserIn,
    UserInfoOut,
    UserLoginRecordsOut,
    UserPatchIn,
)
from flask import Blueprint, jsonify, make_response, request, url_for
from flask_jwt_extended import current_user, get_jwt, jwt_required
from storage import db, db_models
from storage.db_models import LoginRecord
from utils import get_oauth, parse_obj_raise
from werkzeug.exceptions import Forbidden

logger = logging.getLogger(__name__)

v1 = Blueprint("v1", __name__, url_prefix="/api/v1")


@v1.route("/user", methods=["POST"])
def create_user():
    """create_user
    ---
    post:
      description: create_user
      summary: Create user
      requestBody:
        content:
          application/json:
            schema: UserIn

      responses:
        201:
          description: Ok
          headers:
            Location:
              description: uri with user info
              schema:
                type: string
                format: uri
                example: /user/dbdbed6b-95d1-4a4f-b7b9-6a6f78b6726e
          content:
            application/json:
              schema: UserInfoOut
        409:
          description: Conflict
      tags:
        - user
    """
    logger.debug("registration")
    user_data = parse_obj_raise(UserIn, request.get_json())
    logger.info(f"user with email: {user_data.email}")
    user = auth.create_user(user_data.email, user_data.password.get_secret_value())
    resp = make_response("Created", 201)
    resp.headers["Location"] = f"{url_for('.get_user_info', user_id=user.id)}"
    logger.debug(f"location: {resp.headers['Location']}")

    return resp


@v1.route("/user/<string:user_id>", methods=["GET"])
@jwt_required()
def get_user_info(user_id):
    """get_user_info
    ---
    get:
      description: get_user_info
      summary: Get detailed user info
      security:
        - jwt_access: []
      parameters:
      - name: user_id
        in: path
        description: user_id
        schema:
          type: string

      responses:
        200:
          description: Ok
          content:
            application/json:
              schema: UserInfoOut
        401:
          description: Unauthorized
        403:
          description: Forbidden
      tags:
        - user
    """
    logger.debug("get user info")

    if str(current_user.id) != user_id:
        raise Forbidden
    return UserInfoOut(
        id=str(current_user.id),
        email=current_user.email,
        registered_at=current_user.registered_at,
        active=current_user.active,
        roles=[role.name for role in current_user.roles],
    ).dict()


@v1.route("/user/<string:user_id>", methods=["PATCH"])
@jwt_required()
def change_user_info(user_id):
    """change_user_info
    ---
    patch:
      description: change_user_info
      summary: Change user email or password
      security:
        - jwt_access: []
      parameters:
      - name: user_id
        in: path
        description: user_id
        schema:
          type: string
      requestBody:
        content:
          'application/json':
            schema: UserPatchIn

      responses:
        200:
          description: Ok
        401:
          description: Unauthorized
        403:
          description: Forbidden
      tags:
        - user
    """
    logger.debug("change user info")
    if str(current_user.id) != user_id:
        raise Forbidden

    patch_data = parse_obj_raise(UserPatchIn, request.get_json())

    if patch_data.email:
        current_user.email = patch_data.email
    if patch_data.new_password_1:
        current_user.hashed_password = auth.hash_password(
            patch_data.new_password_1.get_secret_value()
        )
    db.session.add(current_user)
    db.session.commit()
    return "OK", 200


@v1.route("/user/<string:user_id>/login_history", methods=["GET"])
@jwt_required()
def get_login_history(user_id):
    """get_login_history
    ---
    get:
      description: get_login_history
      summary: Get login history
      security:
        - jwt_access: []
      parameters:
      - name: user_id
        in: path
        description: user_id
        schema:
          type: string

      responses:
        200:
          description: Return login history
          content:
            application/json:
              schema: UserLoginRecordsOut
        401:
          description: Unauthorized
        403:
          description: Forbidden
      tags:
        - login_history
    """
    logger.debug("get user login history")

    if str(current_user.id) != user_id:
        raise Forbidden

    records = db.session.query(LoginRecord).all()
    login_records = [record.to_api_model() for record in records]
    return UserLoginRecordsOut(logins=login_records).dict()


@v1.route("/token", methods=["POST"])
def create_token_pair():
    """Create token pair.
    ---
    post:
      description: Create token pair
      summary: Create new token pair for device
      requestBody:
        content:
          'application/json':
            schema: TokenInPassword

      responses:
        200:
          description: Return new tokens
          content:
            application/json:
              schema: TokenGrantOut
        400:
          description: Access error
      tags:
        - token
    """
    logger.debug("get token pair")

    # получение токена
    token_data = parse_obj_raise(TokenInPassword, request.get_json())

    user = auth.authenticate_with_email(
        token_data.email, token_data.password.get_secret_value()
    )
    access_token, refresh_token = auth.issue_tokens(
        user, request.user_agent, request.remote_addr
    )
    return jsonify(
        TokenGrantOut(access_token=access_token, refresh_token=refresh_token).dict()
    )


@v1.route("/refresh_token", methods=["POST"])
@jwt_required(refresh=True)
def update_token_pair():
    """update_token_pair
    ---
    post:
      description: update_token_pair
      summary: Revoke current token and create new token pair for device
      security:
        - jwt_refresh: []
      responses:
        200:
          description: OK
          content:
           application/json:
             schema: TokenGrantOut
        401:
          description: Unauthorized
      tags:
        - token
    """
    logger.debug("update token pair")
    token_data = get_jwt()
    access_token, refresh_token = auth.refresh_tokens(current_user, token_data)
    return jsonify(
        TokenGrantOut(access_token=access_token, refresh_token=refresh_token).dict()
    )


@v1.route("/refresh_token", methods=["DELETE"])
@jwt_required()
def revoke_refresh_token():
    """revoke_refresh_token
    ---
    delete:
      description: revoke_refresh_token
      summary: Revoke current refresh_token or all user's refresh_tokens
      security:
        - jwt_access: []
      parameters:
      - name: all
        in: query
        description: whether to logout from all devices
        schema:
          type: boolean

      responses:
        200:
          description: OK
        401:
          description: Unauthorized
      tags:
        - token
    """
    logger.debug("logout")

    if request.args.get("all") == "true":
        auth.logout_all_user_devices(current_user)
    else:
        auth.remove_device_token(current_user, request.user_agent)
    return "OK", 200


# -- OpenID --------------------------------


@v1.route("/oauth_login", methods=["GET"])
def oauth_login():
    """oauth_login
    ---
    get:
      description: Logging in with google openid
      summary: Method for logging in with google openid
      responses:
        200:
          description: OK
      tags:
        - openid
    """
    google = get_oauth().create_client("google")
    redirect_uri = url_for(".oauth_redirect", _external=True)
    return google.authorize_redirect(redirect_uri=redirect_uri)


@v1.route("/oauth_redirect", methods=["GET"])
def oauth_redirect():
    """Redirect URL for openid
    ---
    get:
      description: Redirect URL for openid
      summary: Redirect URL for openid. If user exists - returns token pair,\
       if user is new — creates user.

      responses:
        200:
          description: Return new tokens
          content:
            application/json:
              schema: TokenGrantOut
        201:
          description: Ok
          headers:
            Location:
              description: uri with user info
              schema:
                type: string
                format: uri
                example: /user/dbdbed6b-95d1-4a4f-b7b9-6a6f78b6726e
          content:
            application/json:
              schema: UserInfoOut
        409:
          description: Conflict
      tags:
        - openid
    """
    oauth = get_oauth()
    token = oauth.google.authorize_access_token()
    user_info = oauth.google.parse_id_token(token)

    third_party_id = user_info["sub"]
    user = db_models.User.get_user_universal(third_party_id=third_party_id)
    if user:
        # если пользователь существует, то логиним,
        access_token, refresh_token = auth.issue_tokens(
            user, request.user_agent, request.remote_addr
        )
        return jsonify(
            TokenGrantOut(access_token=access_token, refresh_token=refresh_token).dict()
        )
    else:
        email = user_info["email"] if user_info["email_verified"] else None

        user = auth.create_user_from_third_party(
            third_party_id=third_party_id, email=email
        )
        resp = make_response("Created", 201)
        resp.headers["Location"] = f"{url_for('.get_user_info', user_id=user.id)}"
        logger.debug(f"location: {resp.headers['Location']}")
        return resp


# -- Roles CRUD --------------------------------


@v1.route("/role", methods=["POST"])
@jwt_required()
@auth.require_roles("admin")
def create_role():
    """Create new role
    ---
    post:
      description: Create new role
      summary: Create new role
      security:
        - jwt_access: []

      requestBody:
        content:
          'application/json':
            schema: RoleIn

      responses:
        200:
          description: OK
          content:
            application/json:
              schema: RoleOut
        401:
          description: Unauthorized
      tags:
        - role
    """
    role = RoleIn.parse_obj(request.json)
    created_role = auth.create_role(role)
    return created_role


# remove role
@v1.route("/role/<role_id>", methods=["DELETE"])
@jwt_required()
@auth.require_roles("admin")
def remove_role(role_id: int):
    """Remove role
    ---
    delete:
      description: Remove role
      summary: Remove role
      security:
        - jwt_access: []
      parameters:
        - name: role_id
          in: path
          description: role_id
          schema:
            type: integer

      responses:
        200:
          description: OK
        401:
          description: Unauthorized
      tags:
        - role
    """
    auth.delete_role(role_id)
    return "OK", 200


# add role to user
@v1.route("/role/<role_name>/user/<user_id>", methods=["PUT"])
@jwt_required()
@auth.require_roles("admin")
def add_role_to_user(role_name: str, user_id: str):
    """Add role to user
    ---
    put:
      description: Add role to user
      summary: Add role to user
      security:
        - jwt_access: []
      parameters:
        - name: user_id
          in: path
          description: user_id
          schema:
            type: string
        - name: role_name
          in: path
          description: role_name
          schema:
            type: string

      responses:
        200:
          description: OK
        401:
          description: Unauthorized
      tags:
        - role
    """
    auth.add_role_to_user(role_name, user_id)
    return "OK", 200


# remove role from user
@v1.route("/role/<role_name>/user/<user_id>", methods=["DELETE"])
@jwt_required()
@auth.require_roles("admin")
def remove_role_from_user(role_name: str, user_id: str):
    """Remove role from user
    ---
    delete:
      description: Remove role from user
      summary: Remove role from user
      security:
        - jwt_access: []
      parameters:
        - name: user_id
          in: path
          description: user_id
          schema:
            type: string
        - name: role_name
          in: path
          description: role_name
          schema:
            type: string

      responses:
        200:
          description: OK
        401:
          description: Unauthorized
      tags:
        - role
    """

    auth.remove_role_from_user(role_name, user_id)
    return "OK", 200
