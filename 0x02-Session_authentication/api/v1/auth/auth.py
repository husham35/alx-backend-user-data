#!/usr/bin/env python3
"""API authentication.
"""
from flask import request
import re
from typing import List, TypeVar
from os import getenv


class Auth:
    """
    This class manages the API authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if a paths that require authentication.
        Returns:
        - True or False
        """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True
        path = path + '/' if path[-1] != '/' else path
        for exclude_path in excluded_paths:
            exclude_path = exclude_path.replace('/', '\\/').replace('*', '.*')
            regex = re.compile(exclude_path)
            if regex.search(path):
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

        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Returns None.
        """
        return None

    def session_cookie(self, request=None):
        """
        Return:
            - the value of the cookie request.session_id or None
        """
        if request is None:
            return None

        return request.cookies.get(getenv('SESSION_NAME'))
