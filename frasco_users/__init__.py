from frasco import (Feature, action, current_context, hook, listens_to, command,\
                    signal, flash, request, redirect, current_app, OptionMissingError,
                    InvalidOptionError, populate_obj, Markup, html_tag, url_for, session,
                    lazy_translate, copy_extra_feature_options, translate, current_app)
from frasco.utils import ContextStack
from frasco_models import transaction, as_transaction, save_model
from flask.ext import login
from flask.ext.login import _get_user, login_required, make_secure_token
from flask.ext.bcrypt import Bcrypt
from flask_oauthlib.client import OAuth
from flask import has_request_context, _request_ctx_stack
from werkzeug.local import LocalProxy
from itsdangerous import URLSafeTimedSerializer, BadSignature
from contextlib import contextmanager
import uuid
import datetime
import os
from .blueprint import bp
from .jinja_ext import LoginRequiredExtension, AnonymousOnlyExtension


class UserMixin(login.UserMixin):
    @property
    def is_active(self):
        is_active = getattr(self, 'active_account', None)
        if is_active is None:
            return True
        return is_active

    def get_auth_token(self):
        return self.auth_token_serializer.dumps(self.get_id())


class SignupValidationFailedException(Exception):
    def __init__(self, reason):
        super(SignupValidationFailedException, self).__init__()
        self.reason = reason


current_user = LocalProxy(lambda: current_app.features.users.current)
is_user_logged_in = LocalProxy(lambda: current_app.features.users.logged_in())


class UsersFeature(Feature):
    """User management
    """
    name = "users"
    blueprints = (bp,)
    requires = ["forms", "models"]
    defaults = {"login_view": "users.login",
                "model": "User",
                "username_column": "email",
                "password_column": "password",
                "email_column": "email",
                "username_is_unique": True,
                "email_is_unique": True,
                "must_provide_username": True,
                "must_provide_email": True,
                "allow_email_or_username_login": True,
                "allow_signup": True,
                "forbidden_usernames": [],
                "min_username_length": 1,
                "allow_spaces_in_username": False,
                "username_case_sensitive": False,
                "require_code_on_signup": False,
                "allowed_signup_codes": [],
                "oauth_signup_only": False,
                "oauth_login_only": False,
                "oauth_must_signup": False,
                "oauth_must_provide_password": False,
                "login_user_on_signup": True,
                "login_user_on_reset_password": True,
                "disable_default_authentication": False,
                "default_auth_provider_name": "app",
                "remember_days": 365,
                "reset_password_ttl": 86400,
                "redirect_after_login": "index",
                "redirect_after_signup": "index",
                "redirect_after_signup_disallowed": None, # go to login
                "redirect_after_logout": "index",
                "redirect_after_reset_password_token": False,
                "redirect_after_reset_password": "index",
                "send_welcome_email": False,
                "send_reset_password_email": True,
                "login_error_message": lazy_translate(u"Invalid email or password"),
                "login_disallowed_message": None,
                "login_required_message": lazy_translate(u"Please log in to access this page"),
                "fresh_login_required_message": lazy_translate(u"Please reauthenticate to access this page"),
                "must_provide_username_error_message": lazy_translate(u"A username must be provided"),
                "must_provide_email_error_message": lazy_translate(u"An email address must be provided"),
                "signup_disallowed_message": None,
                "signup_user_exists_message": lazy_translate(u"An account using the same username already exists"),
                "signup_email_exists_message": lazy_translate(u"An account using the same email already exists"),
                "username_too_short_message": lazy_translate(u"The username is too short"),
                "username_has_spaces_message": lazy_translate(u"The username cannot contain spaces"),
                "password_confirm_failed_message": lazy_translate(u"The two passwords do not match"),
                "bad_signup_code_message": lazy_translate(u"The provided code is not valid"),
                "reset_password_token_error_message": lazy_translate(u"This email does not exist in our database"),
                "reset_password_token_success_message": lazy_translate(u"An email has been sent to your email address with a link to reset your password"),
                "reset_password_error_message": lazy_translate(u"Invalid or expired link to reset your password"),
                "reset_password_success_message": lazy_translate(u"Password successfully resetted"),
                "update_password_error_message": lazy_translate(u"Invalid current password"),
                "update_user_email_error_message": lazy_translate(u"An account using the same email already exists"),
                "oauth_user_already_exists_message": lazy_translate(u"This {provider} account has already been used on a different account"),
                "enable_admin": True}

    init_signal = signal('users_init')
    signup_signal = signal('user_signup')
    reset_password_token_signal = signal('user_reset_password_token')
    reset_password_signal = signal('user_reset_password')
    update_user_password_signal = signal('user_update_password')

    ignore_attributes = ['current']

    def init_app(self, app):
        self.app = app

        copy_extra_feature_options(self, app.config)
        app.config.setdefault("REMEMBER_COOKIE_DURATION", datetime.timedelta(days=self.options["remember_days"]))

        self.bcrypt = app.bcrypt = Bcrypt()
        self.token_serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        app.jinja_env.add_extension(LoginRequiredExtension)
        app.jinja_env.add_extension(AnonymousOnlyExtension)
        self.oauth = OAuth()
        self.oauth_apps = []
        self.authentify_handlers = []
        self.signup_code_checker = None
        self.user_validator = None
        self.override_builtin_user_validation = False
        self.login_validator = None

        self.login_manager = login.LoginManager(app)
        self.login_manager.login_view = self.options["login_view"]
        self.login_manager.refresh_view = self.options["login_view"]
        self.login_manager.login_message = self.options["login_required_message"]
        self.login_manager.login_message_category = "warning"
        self.login_manager.needs_refresh_message = self.options["fresh_login_required_message"]
        self.login_manager.needs_refresh_message_category = "warning"

        # this allows to set a current user without a request context
        self.no_req_ctx_user_stack = ContextStack()

        if app.features.exists("emails"):
            app.features.emails.add_templates_from_package(__name__)

        if app.features.exists("babel"):
            app.features.babel.add_extract_dir(os.path.dirname(__file__), ["templates"])

        model = self.model = app.features.models.ensure_model(self.options["model"],
            signup_at=datetime.datetime,
            signup_from=str,
            signup_provider=str,
            auth_providers=list,
            last_login_at=datetime.datetime,
            last_login_from=str,
            last_login_provider=str)

        if UserMixin not in model.__bases__:
            model.__bases__ = (UserMixin,) + model.__bases__
        model.auth_token_serializer = self.token_serializer
        self.query = app.features.models.query(self.options['model'])

        if self.options["username_column"] != self.options["email_column"]:
            app.features.models.ensure_model(model, **dict([
                (self.options["username_column"], dict(type=str, index=True)),
                (self.options["username_column"] + '_lcase', dict(type=str, index=True, unique=self.options["username_is_unique"]))]))

        app.features.models.ensure_model(model, **dict([
            (self.options["email_column"], dict(type=str, index=True, unique=self.options["email_is_unique"])),
            (self.options["password_column"], str)]))

        self.login_manager.user_loader(self.find_by_id)
        self.login_manager.token_loader(self.find_by_token)

        self.init_signal.send(app)

    def init_admin(self, admin, app):
        if self.options['enable_admin']:
            from .admin import create_admin_blueprint
            admin.register_blueprint(create_admin_blueprint(self))
            admin.register_dashboard_counter('Users', lambda: self.query.count(), icon='fa-users')

    def create_oauth_app(self, name, login_view=None, **kwargs):
        app = self.oauth.remote_app(name, **kwargs)
        if login_view:
            self.oauth_apps.append((name, login_view))
        return app

    def add_authentification_handler(self, callback, only=False):
        if only:
            self.authentify_handlers = []
        self.authentify_handlers.append(callback)

    def authentification_handler(self, only=False):
        def decorator(f):
            self.add_authentification_handler(f, only)
            return f
        return decorator

    @property
    def current(self):
        """Returns the current user
        """
        if not has_request_context():
            return self.no_req_ctx_user_stack.top
        user_stack = getattr(_request_ctx_stack.top, 'user_stack', None)
        if user_stack and user_stack.top:
            return user_stack.top
        return _get_user()

    def start_user_context(self, user):
        stack = self.no_req_ctx_user_stack
        if has_request_context():
            if not hasattr(_request_ctx_stack.top, 'user_stack'):
                _request_ctx_stack.top.user_stack = ContextStack()
            stack = _request_ctx_stack.top.user_stack
        stack.push(user)

    def stop_user_context(self):
        stack = self.no_req_ctx_user_stack
        if has_request_context():
            _request_ctx_stack.top.user_stack.pop()
        else:
            self.no_req_ctx_user_stack.pop()

    @contextmanager
    def user_context(self, user):
        self.start_user_context(user)
        try:
            yield user
        finally:
            self.stop_user_context()

    def logged_in(self):
        """Checks if the user is logged in
        """
        return self.current and self.current.is_authenticated

    def find_by_id(self, id):
        return self.query.get(id)

    def find_by_username(self, username):
        ucol = self.options['username_column']
        if not self.options['username_case_sensitive']:
            ucol += '_lcase'
            username = username.lower()
        return self.query.filter((ucol, username.strip())).first()

    def find_by_email(self, email):
        emailcol = self.options['email_column']
        return self.query.filter((emailcol, email.strip().lower())).first()

    def generate_user_token(self, user, salt=None):
        """Generates a unique token associated to the user
        """
        return self.token_serializer.dumps(str(user.id), salt=salt)

    def find_by_token(self, token, salt=None, max_age=None):
        """Loads a user instance identified by the token generated using generate_user_token()
        """
        model = current_app.features.models[self.options["model"]]
        try:
            id = self.token_serializer.loads(token, salt=salt, max_age=max_age)
        except BadSignature:
            return None
        if id is None:
            return None
        return self.find_by_id(id)

    def update_password(self, user, password):
        """Updates the password of a user
        """
        pwcol = self.options["password_column"]
        setattr(user, pwcol, self.bcrypt.generate_password_hash(password))

    def check_password(self, user, password):
        pwcol = self.options['password_column']
        return getattr(user, pwcol, None) and \
            self.bcrypt.check_password_hash(getattr(user, pwcol), password)

    @hook()
    def before_request(self, *args, **kwargs):
        current_context["current_user"] = current_user

    @action()
    def login_required(self, fresh=False, redirect_to=None):
        """Ensures that a user is authenticated
        """
        if not self.logged_in() or (fresh and not self.login_manager.login_fresh()):
            if redirect_to:
                resp = redirect(redirect_to)
            else:
                resp = self.login_manager.unauthorized()
            current_context.exit(resp, trigger_action_group="missing_user")

    @action(default_option="user", defaults=dict(remember=None))
    def login(self, user=None, remember=False, provider=None, form=None, force=False, **attrs):
        if user:
            self._login(user, provider, remember=remember, force=force, **attrs)
            return user

        if self.options["oauth_login_only"]:
            if users.options["login_disallowed_message"]:
                flash(users.options["login_disallowed_message"], "error")
            return redirect(url_for("users.login", next=request.args.get("next")))

        ucol = self.options['username_column']
        pwcol = self.options['password_column']

        if form:
            form = opts["form"]
        elif "form" in current_context.data and request.method == "POST":
            form = current_context.data.form
        else:
            raise OptionMissingError("Missing 'form' option or form for 'login' action")

        user = self.authentify(form[ucol].data, form[pwcol].data)

        if user and self.login_validator and not self.login_validator(user):
            user = None
        if not user:
            if self.options["login_error_message"]:
                flash(self.options["login_error_message"], "error")
            current_context.exit(trigger_action_group="login_failed")

        if remember is None and "remember" in form:
            remember = form["remember"].data
        self._login(user, provider, remember, force, **attrs)

    def authentify(self, username, password):
        for func in self.authentify_handlers:
            user = func(username, password)
            if user:
                return user

        if not self.options["disable_default_authentication"]:
            ucol = self.options['username_column']
            emailcol = self.options['email_column']
            if ucol == emailcol:
                username = username.lower()
            elif not self.options['username_case_sensitive']:
                ucol += '_lcase'
                username = username.lower()
            filters = [(ucol, username.strip())]
            if self.options['allow_email_or_username_login'] and ucol != emailcol:
                filters.extend([(emailcol, username.strip().lower())])
            user = self.query.filter({"$or": filters}).first()
            if user and self.check_password(user, password):
                return user

    @as_transaction
    def _login(self, user, provider=None, remember=False, force=False, **attrs):
        """Updates user attributes and login the user in flask-login
        """
        user.last_login_at = datetime.datetime.now()
        user.last_login_provider = provider or self.options["default_auth_provider_name"]
        user.last_login_from = request.remote_addr
        populate_obj(user, attrs)
        save_model(user)
        login.login_user(user, remember=remember, force=force)

    @action()
    def confirm_login(self):
        """Confirm the login when the session is not fresh
        """
        self.login_manager.confirm_login()

    @action()
    def logout(self):
        login.logout_user()

    @command(with_request_ctx=True)
    @command.arg("username_")
    @command.arg("password")
    @action()
    def signup(self, username_=None, password=None, user=None, form=None, login_user=None, send_email=None,\
               must_provide_password=True, provider=None, **attrs):
        with transaction():
            ucol = self.options['username_column']
            pwcol = self.options['password_column']
            emailcol = self.options['email_column']
            pwconfirmfield = pwcol + "_confirm"

            if not user and not username_ and not form:
                if "form" in current_context.data and request.method == "POST":
                    form = current_context.data.form
                else:
                    raise OptionMissingError(("Missing 'username' and 'password' options or "
                                              "'form' option or form for 'signup' action"))

            if isinstance(username_, self.model):
                user = username_
                username_ = None
            if not user:
                user = self.model()
            if username_:
                setattr(user, ucol, username_)

            if form:
                if must_provide_password:
                    # the password field is manually validated to allow for cases when the
                    # password is not provided and not required (ie. oauth login)
                    if pwcol not in form or not form[pwcol].data.strip():
                        form[pwcol].errors.append(form[pwcol].gettext('This field is required.'))
                        current_context.exit(trigger_action_group="form_validation_failed")
                    self.check_password_confirm(form, "signup_pwd_mismatch")
                    password = form[pwcol].data
                form.populate_obj(user, ignore_fields=[pwcol, pwconfirmfield])

            populate_obj(user, attrs)
            if password:
                self.update_password(user, password)
            if getattr(user, ucol, None):
                setattr(user, ucol, getattr(user, ucol).strip())
            if ucol != emailcol:
                setattr(user, ucol + '_lcase', getattr(user, ucol).lower())
            if getattr(user, emailcol, None):
                setattr(user, emailcol, getattr(user, emailcol).strip().lower())

            try:
                self.validate_user(user, must_provide_password=must_provide_password)
            except SignupValidationFailedException as e:
                current_context["signup_error"] = e.reason
                current_context.exit(trigger_action_group="signup_validation_failed")

            user.signup_at = datetime.datetime.now()
            try:
                user.signup_from = request.remote_addr
            except RuntimeError:
                pass
            user.signup_provider = provider or self.options["default_auth_provider_name"]
            user.auth_providers = [user.signup_provider]
            with transaction():
                save_model(user)
            self.post_signup(user, login_user, send_email)
            return user

    def check_password_confirm(self, form, trigger_action_group=None):
        """Checks that the password and the confirm password match in
        the provided form. Won't do anything if any of the password fields
        are not in the form.
        """
        pwcol = self.options['password_column']
        pwconfirmfield = pwcol + "_confirm"
        if pwcol in form and pwconfirmfield in form and form[pwconfirmfield].data != form[pwcol].data:
            if self.options["password_confirm_failed_message"]:
                flash(self.options["password_confirm_failed_message"], "error")
            current_context.exit(trigger_action_group=trigger_action_group)

    def check_signup_code(self, code):
        if self.signup_code_checker:
            return self.signup_code_checker(code)
        return code in self.options['allowed_signup_codes']

    def validate_user(self, user=None, username=None, email=None, password=None, ignore_user_id=None,
                      must_provide_password=False, flash_messages=True, raise_error=True):
        """Validates a new user object before saving it in the database.
        Checks if a password is present unless must_provide_password is False.
        Checks if the username is unique unless the option username_is_unique is set to False.
        If the email column exists on the user object and the option email_is_unique is set to True,
        also checks if the email is unique.
        """
        ucol = self.options['username_column']
        emailcol = self.options['email_column']
        if user:
            username = getattr(user, ucol, None)
            email = getattr(user, emailcol, None)
            password = getattr(user, self.options["password_column"], None)
            ignore_user_id = getattr(user, 'id', None)
        if username is not None:
            username = username.strip()
        if email is not None:
            email = email.strip().lower()

        if must_provide_password and not password:
            if raise_error:
                raise SignupValidationFailedException("password_missing")
            return False

        if self.user_validator and self.override_builtin_user_validation:
            if not self.user_validator(username, email, password):
                if raise_error:
                    raise SignupValidationFailedException("failed_validation")
                return False
            return True

        if ucol != emailcol and self.options["must_provide_username"]:
            if not username:
                if flash_messages and self.options["must_provide_username_error_message"]:
                    flash(self.options["must_provide_username_error_message"], "error")
                if raise_error:
                    raise SignupValidationFailedException("username_missing")
                return False
            if username.lower() in self.options['forbidden_usernames']:
                if flash_messages and self.options["signup_user_exists_message"]:
                    flash(self.options["signup_user_exists_message"], "error")
                if raise_error:
                    raise SignupValidationFailedException("username_forbidden")
                return False
            if len(username) < self.options['min_username_length']:
                if flash_messages and self.options["username_too_short_message"]:
                    flash(self.options["username_too_short_message"], "error")
                if raise_error:
                    raise SignupValidationFailedException("username_too_short")
                return False
            if not self.options['allow_spaces_in_username'] and " " in username:
                if flash_messages and self.options["username_has_spaces_message"]:
                    flash(self.options["username_has_spaces_message"], "error")
                if raise_error:
                    raise SignupValidationFailedException("username_has_spaces")
                return False
        if ucol != emailcol and username and self.options["username_is_unique"]:
            col = ucol if self.options["username_case_sensitive"] else ucol + '_lcase'
            uname = username if self.options["username_case_sensitive"] else username.lower()
            q = self.query.filter((col, uname))
            if ignore_user_id:
                q = q.filter(("id__ne", ignore_user_id))
            if q.count() > 0:
                if flash_messages and self.options["signup_user_exists_message"]:
                    flash(self.options["signup_user_exists_message"], "error")
                if raise_error:
                    raise SignupValidationFailedException("user_exists")
                return False
        if self.options["must_provide_email"] and not email:
            if flash_messages and self.options["must_provide_email_error_message"]:
                flash(self.options["must_provide_email_error_message"], "error")
            if raise_error:
                raise SignupValidationFailedException("email_missing")
            return False
        if self.options["email_is_unique"] and email:
            q = self.query.filter((emailcol, email))
            if ignore_user_id:
                q = q.filter(("id__ne", ignore_user_id))
            if q.count() > 0:
                if flash_messages and self.options["signup_email_exists_message"]:
                    flash(self.options["signup_email_exists_message"], "error")
                if raise_error:
                    raise SignupValidationFailedException("email_exists")
                return False

        if self.user_validator and not self.user_validator(username, email, password):
            if raise_error:
                raise SignupValidationFailedException("failed_validation")
            return False

        return True

    def post_signup(self, user, login_user=None, send_email=None):
        """Executes post signup actions: sending the signal, logging in the user and
        sending the welcome email
        """
        self.signup_signal.send(self, user=user)

        if (login_user is None and self.options["login_user_on_signup"]) or login_user:
            self._login(user, user.signup_provider)

        to_email = getattr(user, self.options["email_column"], None)
        if to_email and ((send_email is None and self.options["send_welcome_email"]) or send_email):
            template = "users/welcome.txt" if self.options["send_welcome_email"] == True else self.options["send_welcome_email"]
            current_app.features.emails.send(to_email, template, user=user)

    @action(default_option="user")
    def gen_reset_password_token(self, user=None, send_email=None):
        """Generates a reset password token and optionnaly (default to yes) send the reset
        password email
        """
        if not user and "form" in current_context.data and request.method == "POST":
            form = current_context.data.form
            user = self.find_by_email(form[self.options["email_column"]].data)
            if user is None:
                if self.options["reset_password_token_error_message"]:
                    flash(self.options["reset_password_token_error_message"], "error")
                current_context.exit(trigger_action_group="reset_password_failed")
                
        if not user:
            raise InvalidOptionError("Invalid user in 'reset_password_token' action")

        token = self.generate_user_token(user, salt="password-reset")
        self.reset_password_token_signal.send(self, user=user, token=token)
        if (send_email is None and self.options["send_reset_password_email"]) or send_email:
            to_email = getattr(user, self.options["email_column"])
            current_app.features.emails.send(to_email, "users/reset_password.txt", user=user, token=token)
        return token

    @command("send-reset-password")
    def send_reset_password_command(self, email, send_email=True):
        user = self.find_by_email(email)
        if not user:
            raise Exception("User '%s' not found" % email)
        token = self.gen_reset_password_token(user, send_email)
        command.echo(url_for("users.reset_password", token=token, _external=True))

    @action(default_option="token")
    def reset_password(self, token=None, login_user=None):
        """Resets the password of the user identified by the token
        """
        pwcol = self.options['password_column']
        if not token:
            if "token" in request.view_args:
                token = request.view_args["token"]
            elif "token" in request.values:
                token = request.values["token"]
            else:
                raise OptionMissingError(("Missing 'token' option or 'token' view arg "
                                          "or 'token' GET paramater in 'reset_password' action"))

        user = self.find_by_token(token, salt="password-reset", max_age=self.options["reset_password_ttl"])
        if user is None:
            if self.options["reset_password_error_message"]:
                flash(self.options["reset_password_error_message"], "error")
            current_context.exit(trigger_action_group="reset_password_failed")

        self.update_password_from_form(user)
        self.reset_password_signal.send(self, user=user)
        if (login_user is None and self.options["login_user_on_reset_password"]) or login_user:
            login.login_user(user)
        return user

    @command("reset-password")
    def reset_password_command(self, username, password):
        with transaction():
            user = self.find_by_username(username)
            if not user:
                raise Exception("User '%s' not found" % username)
            self.update_password(user, password)
            save_model(user)

    @action("update_user_password", default_option="user")
    @as_transaction
    def update_password_from_form(self, user=None, form=None):
        """Updates the user password using a form
        """
        user = user or self.current
        if not form and "form" in current_context.data and request.method == "POST":
            form = current_context.data.form
        elif not form:
            raise OptionMissingError("Missing a form in 'update_user_password' action")

        self._update_password_from_form(user, form)
        save_model(user)
        self.update_user_password_signal.send(self, user=user)

    def _update_password_from_form(self, user, form):
        pwcol = self.options['password_column']
        pwcurrentcol = pwcol + "_current"
        pwconfirmcol = pwcol + "_confirm"
        current_pwd = getattr(user, pwcol)
        if current_pwd and pwcurrentcol in form and not self.bcrypt.check_password_hash(current_pwd, form[pwcurrentcol].data):
            if self.options["update_password_error_message"]:
                flash(self.options["update_password_error_message"], "error")
            current_context.exit(trigger_action_group="reset_password_current_mismatch")
        self.check_password_confirm(form, "reset_password_confirm_mismatch")
        self.update_password(user, form[pwcol].data)

    @action(default_option="user")
    def check_user_password(self, user, password=None, form=None):
        """Checks if the password matches the one of the user. If no password is
        provided, the current form will be used
        """
        pwcol = self.options['password_column']
        if password is None:
            if not form and "form" in current_context.data and request.method == "POST":
                form = current_context.data.form
            if form:
                password = form[pwcol].data
            else:
                raise OptionMissingError("Missing 'password' option or a form")
        current_pwd = getattr(user, pwcol)
        if not current_pwd or not self.bcrypt.check_password_hash(current_pwd, password):
            current_context.exit(trigger_action_group="password_mismatch")

    @action(default_option="user")
    @as_transaction
    def update_user_from_form(self, user, form=None):
        ucol = self.options["username_column"]
        emailcol = self.options["email_column"]
        pwcol = self.options['password_column']
        if not form and "form" in current_context.data and request.method == "POST":
            form = current_context.data.form
        elif not form:
            raise OptionMissingError("Missing form")

        username = form[ucol].data if ucol in form else user.username
        email = form[emailcol].data if emailcol in form else user.email

        try:
            self.validate_user(username=username, email=email, ignore_user_id=user.id)
        except SignupValidationFailedException as e:
            current_context["validation_error"] = e.reason
            current_context.exit(trigger_action_group="user_update_validation_failed")

        if pwcol in form and form[pwcol].data:
            self._update_password_from_form(user, form)

        form.populate_obj(user, ignore_fields=[pwcol])
        if ucol in form:
            setattr(user, ucol + '_lcase', form[ucol].data.lower().strip())
        if emailcol in form:
            setattr(user, emailcol, form[emailcol].data.lower().strip())

        save_model(user)

    @action("check_user_unique_attr", default_option="attrs")
    def check_unique_attr(self, attrs, user=None, form=None, flash_msg=None):
        """Checks that an attribute of the current user is unique amongst all users.
        If no value is provided, the current form will be used.
        """
        user = user or self.current
        ucol = self.options["username_column"]
        email = self.options["email_column"]
        if not isinstance(attrs, (list, tuple, dict)):
            attrs = [attrs]

        for name in attrs:
            if isinstance(attrs, dict):
                value = attrs[name]
            else:
                form = form or current_context.data.get("form")
                if not form:
                    raise OptionMissingError("Missing 'value' option or form in 'check_user_unique_attr' action")
                value = form[name].data

            if name == ucol and not self.options["username_case_sensitive"]:
                filters = (ucol + '_lcase', value.strip().lower())
            elif name == emailcol:
                filters = (emailcol, value.strip().lower())
            else:
                filters = (name, value.strip())

            if self.query.filter({"$and": [filters, ("id__ne", user.id)]}).count() > 0:
                if flash_msg is None:
                    flash_msg = "The %s is already in use" % name
                if flash_msg:
                    flash(flash_msg, "error")
                current_context.exit(trigger_action_group="user_attr_not_unique")

    def oauth_login(self, provider, id_column, id, attrs, defaults, redirect_url=None):
        """Execute a login via oauth. If no user exists, oauth_signup() will be called
        """
        user = self.query.filter(**dict([(id_column, id)])).first()
        if not redirect_url:
            redirect_url = request.args.get('next') or url_for(self.options["redirect_after_login"])
        if self.logged_in():
            if user and user != self.current:
                if self.options["oauth_user_already_exists_message"]:
                    flash(self.options["oauth_user_already_exists_message"].format(provider=provider), "error")
                return redirect(redirect_url)
            if provider not in self.current.auth_providers:
                self.current.auth_providers.append(provider)
            current_app.features.models.save(self.current, **attrs)
        elif not user:
            return self.oauth_signup(provider, attrs, defaults)
        else:
            self.login(user, provider=provider, **attrs)
        return redirect(redirect_url)

    def oauth_signup(self, provider, attrs, defaults):
        """Start the signup process after having logged in via oauth
        """
        session["oauth_user_defaults"] = defaults
        session["oauth_user_attrs"] = dict(provider=provider, **attrs)
        return redirect(url_for('users.oauth_signup', next=request.args.get("next")))

    @command("show")
    def show_user_command(self, username):
        user = self.find_by_username(username)
        if not user:
            raise Exception("User '%s' not found" % username)
        command.echo(user.for_json())