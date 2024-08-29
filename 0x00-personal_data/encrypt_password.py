#!/usr/bin/env python3
"""
A module for encrypting user passwords with.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using a random salt.
    Args:
        password: string type
    Returns: a salted, hashed password, which is a byte string.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Checks if a hashed password was formed from the given user password.
    Args:
        hashed_password: bytes type
        password: string type
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
