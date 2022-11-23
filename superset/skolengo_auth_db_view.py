import jwt
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder.api import expose
import flask_jwt_extended
from flask_jwt_extended import jwt_required
from superset.security.manager import SupersetSecurityManager
from flask_sqlalchemy_rls import SQLAlchemy
#from superset.connectors.sqla.models import RowLevelSecurityFilter
from flask import request, flash, redirect
from flask_login import login_user, logout_user
from superset import security_manager
import json
from flask import Flask, render_template, jsonify
import requests
import os
from flask import request

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager

class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'

    @jwt_required()
    def get(self):
        return {"State": "Success"}

    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        token = request.args.get('token')
        if not token:
            token = request.cookies.get('access_token')
        if token is not None:
            jwt_payload = jwt.decode(token, 'test-guest-secret-change-me', algorithms=['HS256'])
            code_site = jwt_payload.get("codeSite")
            user = {"username": "test_guest"}
            resources = [{"some": "resource"}]
            rls = [{"dataset": 1, "clause": "codeSite = 10461"}]
            user = self.appbuilder.sm.find_user(username=code_site)
            #token = security_manager.create_guest_access_token(user, resources, rls)
            if not user:
                SQLAlchemy.create_session(self)
                rls = RowLevelSecurityFilter()
                rls.clause = 'codeSite = 10461'
                role_admin = self.appbuilder.sm.add_role(code_site)
                rls.roles = self.appuilder.sm.get_role(code_site)
                db.commit(rls)
                # user = self.appbuilder.sm.add_user(user_name, user_name, 'aimind',
                #                                    user_name + "@aimind.com",
                #                                    role_admin,
                #                                    password="aimind" + user_name)
            if user:
                login_user(user, remember=False)
                redirect_url = request.args.get('redirect')
                if not redirect_url:
                    redirect_url = self.appbuilder.get_url_for_index
                return redirect(redirect_url)
            else:
                return super(CustomAuthDBView, self).login()
        else:
            flash('Unable to auto login', 'warning')
            return super(CustomAuthDBView, self).login()

    @expose("/guest-token/", methods=['GET', 'POST'])
    def guest_token(self):
        token = request.args.get('token')
        if not token:
            token = request.cookies.get('access_token')
        if token is not None:
            jwt_payload = jwt.decode(token, 'test-guest-secret-change-me',
                                     algorithms=['HS256'])

        user = {"username": "test_guest"}
        resources = [{"some": "resource"}]
        rls = [{"dataset": 1, "clause": "access = 1"}]

        access_token = security_manager.create_guest_access_token(user, resources, rls)
        # access_token = create_access_token(identity=user)

        bearer_token = "Bearer " + access_token
        response2 = requests.post(
            "http://localhost:8080/login",
            headers={"Authorization": bearer_token, 'Accept': 'application/json',
                     'Content-Type': 'application/json'})
        # create_access_token()

        return response2

    @expose("/protected", methods=["GET"])
    @jwt_required()
    def protected(self):
        # Access the identity of the current user with get_jwt_identity
        return jsonify(token=get_jwt_identity())
        # redirect_url = self.appbuilder.get_url_for_index
        # return redirect(redirect_url)
class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView
