import logging
import uuid
from datetime import datetime
from typing import Optional

from api.models import UserLoginRecord
from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import backref, relationship
from storage.db import Base, session
from werkzeug.exceptions import NotFound

logger = logging.getLogger(__name__)


class User(Base):
    __tablename__ = "users"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    email = Column(String(255), unique=True, nullable=True)
    hashed_password = Column("password", String(255), nullable=False)
    registered_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    active = Column(Boolean, default=True, nullable=False)
    roles = relationship(
        "Role",
        secondary="roles_users",
        backref=backref("users", lazy="dynamic"),
    )

    logins = relationship(
        "LoginRecord",
        lazy="dynamic",
        cascade="all, delete-orphan",
        backref=backref("user"),
    )

    should_change_password = Column(Boolean, default=False)

    @classmethod
    def from_credentials(cls, email, hashed_password) -> "User":
        return cls(email=email, hashed_password=hashed_password)

    def __repr__(self):
        return f"{self.__class__.__name__}: {self.email}, active: {self.active}, \
        registered_at: {self.registered_at.date().isoformat()}>"

    @classmethod
    def get_by_id(cls, user_id) -> Optional["User"]:
        return session.query(cls).filter_by(id=user_id).one_or_none()

    @classmethod
    def get_user_universal(
        cls, email: Optional[str] = None, third_party_id: Optional[str] = None
    ):
        logger.debug(f"get_user_universal: {email=}, {third_party_id=}")
        user = (
            session.query(cls)
            .join(cls.third_party_accounts, full=True)
            .filter((cls.email == email) | (ThirdPartyAccount.id == third_party_id))
            .one_or_none()
        )
        logger.debug(f"{user=}")
        return user

    @property
    def permissions(self):
        permissions_set = set()
        for role in self.roles:
            permissions_set.update(role.permissions)
        return list(permissions_set)


class ThirdPartyAccount(Base):
    __tablename__ = "third_party_accounts"
    id = Column(String, primary_key=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    user = relationship(
        "User", backref=backref("third_party_accounts", cascade="all, delete-orphan")
    )
    third_party_name = Column(String)
    user_info = Column(JSON)

    def __repr__(self):
        return f"{self.__class__.__name__}: {self.id} (user_id: {self.user.id})"


class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, unique=True)
    name = Column(String(80), unique=True)
    description = Column(String(255), nullable=True)
    permissions = Column(ARRAY(String, dimensions=1), default=[])

    @classmethod
    def get(cls, name):
        role = session.query(cls).filter_by(name=name).one_or_none()
        if not role:
            raise NotFound(f"Role with name {name} is not found")

    # permissions = relationship(
    #     "Permission",
    #     secondary="roles_permisssions",
    #     backref=backref("roles", lazy="dynamic"),
    # )

    def __repr__(self):
        return f"{self.__class__.__name__}: {self.name}({self.id}) - {self.description}"


class RolesUsers(Base):
    __tablename__ = "roles_users"
    id = Column(Integer, primary_key=True)
    user_id = Column("user_id", UUID(as_uuid=True), ForeignKey("users.id"))
    role_id = Column("role_id", Integer, ForeignKey("roles.id"))


#
# class Permission(Base):
#     __tablename__ = "permissions"
#     id = Column(Integer, primary_key=True, unique=True)
#     name = Column(String(80), unique=True)
#     description = Column(String(255), nullable=True)
#
#     def __repr__(self):
#         return f"{self.__class__.__name__}: {self.name}({self.id}) - {self.description}"

#
# class RolesPermissions(Base):
#     __tablename__ = "roles_permisssions"
#     id = Column(Integer, primary_key=True)
#     permission_id = Column("permission_id", Integer, ForeignKey("permissions.id"))
#     role_id = Column("role_id", Integer, ForeignKey("roles.id"))
#


class LoginRecord(Base):
    __tablename__ = "login_entries"
    id = Column(Integer, primary_key=True, unique=True)
    user_id = Column("user_id", UUID(as_uuid=True), ForeignKey("users.id"))
    user_agent = Column(String)
    platform = Column(String(100))
    browser = Column(String(255))
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip = Column(String(100))

    def __init__(self, user_id, platform, browser, user_agent, ip):
        self.user_id = user_id
        self.platform = platform
        self.browser = browser
        self.user_agent = user_agent
        self.ip = ip

    def to_api_model(self) -> UserLoginRecord:
        return UserLoginRecord(
            user_agent=self.user_agent,
            platform=self.platform,
            browser=self.browser,
            timestamp=self.timestamp,
            ip=self.ip,
        )
