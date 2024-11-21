#!/usr/bin/env python3
"""Hash password"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid
from typing import Optional


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            pass
        hashed_password = _hash_password(password)
        new_user = self._db.add_user(email, hashed_password)
        return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Credentials validation"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                encode_pass = password.encode('utf-8')
                pass_bytes = user.hashed_password
                return bcrypt.checkpw(encode_pass, pass_bytes)
            else:
                return False
        except NoResultFound:
            return False

    def create_session(self, email: str) -> Optional[str]:
        """Get session ID"""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return

    def get_user_from_session_id(self, session_id: str) -> Optional[str]:
        """Find user by session ID"""
        try:
            user = self._db.find_user_by(session_id=session_id)
            if user:
                return user
            return None
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroy session"""
        if user_id is None:
            return None
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generate reset password token"""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                token = _generate_uuid()
                self._db.update_user(user.id, reset_token=token)
                return token
            else:
                raise ValueError
        except Exception:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """Update password"""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except Exception:
            raise ValueError
        hashed_pass = _hash_password(password)
        self._db.update_user(user.id, hashed_pass=hashed_pass)
        self._db.update_user(user.id, reset_token=None)


def _hash_password(password: str) -> bytes:
    """Return password as bytes"""
    bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(bytes, salt)
    return hashed


def _generate_uuid() -> str:
    """Return a string representation of a new UUID"""
    return str(uuid.uuid1())
