import logging.config

import defaults
import jwt
import uvicorn as uvicorn
from api_v1 import film, genre, person
from config import config
from db import cache, elastic
from elasticsearch import AsyncElasticsearch
from fastapi import FastAPI
from fastapi.responses import ORJSONResponse
from jwt import PyJWTError
from permissions import Permissions
from registry import filter_suspicious
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
)
from starlette.middleware.authentication import AuthenticationMiddleware


class JWTAuthBackend(AuthenticationBackend):
    async def authenticate(self, request):
        # Get JWT token from user's cookies

        if "Authorization" not in request.headers:
            logging.debug("no auth")
            return

        auth = request.headers["Authorization"]
        try:
            scheme, token = auth.split()
            if scheme.lower() != "bearer":
                logging.debug("not bearer auth")
                return
        except ValueError:
            logging.debug(f"Invalid authorization header: {auth}")
            raise AuthenticationError("Invalid authorization")

        # Returns UnauthenticatedUser if token does not exists in header
        if not token:
            logging.debug("no token")
            return

        # Checks the validity of the JWT token, if token is invalid returns UnauthenticatedUser object
        try:
            jwt_decoded = jwt.decode(
                token, config.JWT_PUBLIC_KEY, algorithms=[config.JWT_ALGORITHM]
            )
        except PyJWTError as err:
            logging.error(str(err))
            logging.exception("invalid token, user is unauthenticated")
            raise AuthenticationError("Invalid credentials")

        # In case if token is valid returns an object of the authorized user
        permissions = jwt_decoded["permissions"]
        if Permissions.SUSPICIOUS_READ in permissions:
            filter_suspicious.set(False)
        logging.debug(
            f"token is valid, user: {jwt_decoded['sub']} permissions: {permissions}, jwt: {jwt_decoded}"
        )
        return AuthCredentials(permissions), SimpleUser(jwt_decoded["sub"])


app = FastAPI(
    title="Films API",
    docs_url="/swagger",
    openapi_url="/swagger.json",
    default_response_class=ORJSONResponse,
)
app.add_middleware(AuthenticationMiddleware, backend=JWTAuthBackend())


@app.on_event("startup")
async def startup():
    logging.config.dictConfig(defaults.LOGGING)

    await cache.get_cache_storage()
    elastic.es = AsyncElasticsearch(config.ES_URL)


@app.on_event("shutdown")
async def shutdown():
    await cache.cache.close()
    await elastic.es.close()


app.include_router(film.router, prefix="/v1/film", tags=["film"])
app.include_router(person.router, prefix="/v1/person", tags=["person"])
app.include_router(genre.router, prefix="/v1/genre", tags=["genre"])

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        log_config=defaults.LOGGING,
        log_level=logging.DEBUG,
    )
