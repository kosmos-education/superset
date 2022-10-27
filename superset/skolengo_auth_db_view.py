import jwt
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder.api import expose
from superset.security.manager import SupersetSecurityManager
#from superset.connectors.sqla.models import RowLevelSecurityFilter
from flask import request, flash, redirect
from flask_login import login_user, logout_user
from superset import security_manager

class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'

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
            rls = [{"dataset": 1, "clause": "access = 1"}]
            user = self.appbuilder.sm.find_user(username=code_site)
            #token = security_manager.create_guest_access_token(user, resources, rls)
            if not user:
                # rls = RowLevelSecurityFilter()
                # rls.clause = 'codeSite = 10461'
                # role_admin = self.appbuilder.sm.add_role(code_site)
                # rls.roles = self.appuilder.sm.get_role(code_site)
                user = self.appbuilder.sm.add_user(user_name, user_name, 'aimind',
                                                   user_name + "@aimind.com",
                                                   role_admin,
                                                   password="aimind" + user_name)
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


class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView
