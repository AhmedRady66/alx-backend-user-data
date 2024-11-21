#!/usr/bin/env python3
"""Hash password"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """Return password as bytes"""
    bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(bytes, salt)
    return hashed
