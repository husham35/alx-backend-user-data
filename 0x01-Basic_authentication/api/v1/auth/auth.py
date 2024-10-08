#!/usr/bin/env python3
"""API authentication.
"""
from flask import request
import re
from typing import List, TypeVar


class Auth:
    """
    Returns Autentication for now.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if a paths that require authentication.
        Returns:
        - True or False
        """
        if path is not None and excluded_paths is not None:
            for exclusion_path in map(lambda x: x.strip(), excluded_paths):
                pattern = ''
                if exclusion_path[-1] == '*':
                    pattern = '{}.*'.format(exclusion_path[0:-1])
                elif exclusion_path[-1] == '/':
                    pattern = '{}/*'.format(exclusion_path[0:-1])
                else:
                    pattern = '{}/*'.format(exclusion_path)
                if re.match(pattern, path):  # use regex to match pattern
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the value of the Authorization header from the
        request object.
        Returns:
        - None or the authorization header
        """
        if request is None:
            return None

        auth_header = request.headers.get('Authorization')
        if auth_header is None:
            return None

        return auth_header

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Returns None.
        """
        return None
