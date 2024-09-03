#!/usr/bin/env python3
"""Basic authentication module for the API.
"""
import base64
import binascii
from .auth import Auth
from models.user import User
import re
from typing import Tuple, TypeVar


class BasicAuth(Auth):
    """
    Basic Auth class inherits from Auth class.
    """
    def extract_base64_authorization_header(
            self,
            authorization_header: str) -> str:
        """
        Retrieves the Base64 part of the Authorization header
        for a Basic Authentication.
        Returns:
        - None if authorization_header is either None, not a string, or
          doesn't start by Basic, else the value after Basic.
        """
        if isinstance(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'  # define regex pattern
            patt_match = re.fullmatch(pattern, authorization_header.strip())
            if patt_match is not None:
                return patt_match.group('token')
        return None

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str,
            ) -> str:
        """
        Decodes a base64-encoded authorization header.
        Returns:
        - None if base64_authorization_header is either None, not a string, or
          is not a valid Base64, else the decoded value as UTF8 string.
        """
        if isinstance(base64_authorization_header) == str:
            try:
                res = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str,
            ) -> Tuple[str, str]:
        """
        Retrieves user credentials from a base64-decoded authorization
        header.
        Returns:
        - None, None if decoded_base64_authorization_header is None, is not a
        string, doesn't contain `:`, else the email and user password
        """
        if isinstance(decoded_base64_authorization_header) == str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            patt_match = re.fullmatch(
                pattern,
                decoded_base64_authorization_header.strip(),
            )
            if patt_match is not None:
                user = patt_match.group('user')
                password = patt_match.group('password')
                return user, password
        return None, None

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """
        Retrieves a user based on the user's credentials.
        Returns:
        - None if user_email and user_pwd is either None, not a string,
          if your database (file) doesn’t contain any User instance with
          email equal to user_email, user_pwd is not the password of the user,
          else the found user
        """
        if isinstance(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user from a request.
        Returns:
        - the user instance of a request
        """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
