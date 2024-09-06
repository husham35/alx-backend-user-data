#!/usr/bin/env python3
"""
SessionAuth module for the API
"""
from api.v1.auth.auth import Auth
from models.user import User
from uuid import uuid4


class SessionAuth(Auth):
    """
    This class uses session to manage the API authentication
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Creates a Session ID for a user_id
        Returns:
         - None if user_id is None or not a string, else uuid4 id in Base
        """
        if user_id is None or type(user_id) != str:
            return None

        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Retrieves a User ID based on a Session ID
        Returns:
         - None if user_id is None or not a string, User ID for the key
           session_id
        """
        if session_id is None or type(session_id) != str:
            return None

        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """
        Returns a User instance based on a cookie value
        """
        session_cookie = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_cookie)

        return User.get(user_id)

    def destroy_session(self, request=None):
        """
        Deletes the user session / logout
        Returns:
         - True or False
        """
        if request is None:
            return False

        session_cookie = self.session_cookie(request)

        if not session_cookie:
            return False

        user_id = self.user_id_for_session_id(session_cookie)

        if not user_id:
            return False

        del self.user_id_by_session_id[session_cookie]

        return True
