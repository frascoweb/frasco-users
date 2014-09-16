from frasco import (Feature, action, current_context, hook, listens_to, command,\
                    signal, flash, request, redirect, current_app, OptionMissingError,
                    InvalidOptionError, populate_obj, Markup, html_tag, url_for, session,
                    lazy_translate, copy_extra_feature_options, translate)
from flask.ext import login
from flask.ext.login import current_user, login_required, make_secure_token
from flask.ext.bcrypt import Bcrypt
from flask_oauth import OAuth
from itsdangerous import URLSafeTimedSerializer, BadSignature
import uuid
import datetime
import os
from .blueprint import bp
from .jinja_ext import LoginRequiredExtension, AnonymousOnlyExtension


class UserMixin(login.UserMixin):
    auth_token_columns = None

    def get_id(self):
        return str(self._id)

    def is_active(self):
        if "is_active" not in self:
            return True
        return self.is_active

    def get_auth_token(self):
        return self.auth_token_serializer.dumps(self.pk())


class SignupValidationFailedException(Exception):
    def __init__(self, reason):
        super(SignupValidationFailedException, self).__init__()
        self.reason = reason


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
                "allow_signup": True,
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
                "redirect_after_login": "main.index",
                "redirect_after_signup": "main.index",
                "redirect_after_signup_disallowed": None, # go to login
                "redirect_after_logout": "main.index",
                "redirect_after_reset_password_token": False,
                "redirect_after_reset_password": "main.index",
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
                "password_confirm_failed_message": lazy_translate(u"The two passwords do not match"),
                "reset_password_token_error_message": lazy_translate(u"This email does not exist in our database"),
                "reset_password_token_success_message": lazy_translate(u"An email has been sent to your email address with a link to reset your password"),
                "reset_password_error_message": lazy_translate(u"Invalid or expired link to reset your password"),
                "reset_password_success_message": lazy_translate(u"Password successfully resetted"),
                "update_password_error_message": lazy_translate(u"Invalid current password"),
                "update_user_email_error_message": lazy_translate(u"An account using the same email already exists"),
                "oauth_user_already_exists_message": lazy_translate(u"This %(provider)s account has already been used on a different account")}

    signup_signal = signal('user_signup')
    reset_password_token_signal = signal('user_reset_password_token')
    reset_password_signal = signal('user_reset_password')
    update_user_password_signal = signal('user_update_password')

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

        self.login_manager = login.LoginManager(app)
        self.login_manager.login_view = self.options["login_view"]
        self.login_manager.refresh_view = self.options["login_view"]
        self.login_manager.login_message = self.options["login_required_message"]
        self.login_manager.login_message_category = "warning"
        self.login_manager.needs_refresh_message = self.options["fresh_login_required_message"]
        self.login_manager.needs_refresh_message_category = "warning"

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

        model.__bases__ = (UserMixin,) + model.__bases__
        model.auth_token_serializer = self.token_serializer
        self.query_model = app.features.models.query(model)

        if self.options["username_column"] != self.options["email_column"]:
            app.features.models.ensure_model(model, **dict([
                (self.options["username_column"], dict(index=True, unique=self.options["username_is_unique"]))]))

        app.features.models.ensure_model(model, **dict([
            (self.options["email_column"], dict(type=str, index=True, unique=self.options["email_is_unique"])),
            (self.options["password_column"], str)]))

        @self.login_manager.user_loader
        def user_loader(pk):
            return self.query_model.get(pk)

        @self.login_manager.token_loader
        def token_loader(token):
            return self.load_user_from_token(token)

    def init_admin(self, admin):
        admin.register_blueprint("frasco_users.admin:bp")

    def create_oauth_app(self, name, login_view=None, **kwargs):
        app = self.oauth.remote_app(name, **kwargs)
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
        return current_user

    def logged_in(self):
        """Checks if the user is logged in
        """
        return current_user.is_authenticated()

    def get_by_username(self, username):
        return self.query_model.filter_by(**dict([(self.options['username_column'], username)])).first()

    def generate_user_token(self, user, salt=None):
        """Generates a unique token associated to the user
        """
        return self.token_serializer.dumps(user.pk(), salt=salt)

    def load_user_from_token(self, token, salt=None, max_age=None):
        """Loads a user instance identified by the token generated using generate_user_token()
        """
        model = current_app.features.models[self.options["model"]]
        try:
            pk = self.token_serializer.loads(token, salt=salt, max_age=max_age)
        except BadSignature:
            return None
        if pk is None:
            return None
        return model.query_model.get(pk)

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
    def login_required(self, fresh=False):
        """Ensures that a user is authenticated
        """
        if not current_user.is_authenticated() or (fresh and not self.login_manager.login_fresh()):
            current_context.exit(self.login_manager.unauthorized(), trigger_action_group="missing_user")

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
            user = self.query_model.filter_by(**dict([(self.options['username_column'], username)])).first()
            if user and self.check_password(user, password):
                return user

    def _login(self, user, provider=None, remember=False, force=False, **attrs):
        """Updates user attributes and login the user in flask-login
        """
        user.last_login_at = datetime.datetime.now()
        user.last_login_provider = provider or self.options["default_auth_provider_name"]
        user.last_login_from = request.remote_addr
        populate_obj(user, attrs)
        current_app.features.models.save(user)
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
        ucol = self.options['username_column']
        pwcol = self.options['password_column']
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

        try:
            self.validate_signuping_user(user, must_provide_password=must_provide_password)
        except SignupValidationFailedException as e:
            current_context["signup_error"] = e.reason
            current_context.exit(trigger_action_group="signup_validation_failed")

        user.signup_at = datetime.datetime.now()
        user.signup_from = request.remote_addr
        user.signup_provider = provider or self.options["default_auth_provider_name"]
        user.auth_providers = [user.signup_provider]

        current_app.features.models.save(user)
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

    def validate_signuping_user(self, user, must_provide_password=False, flash_messages=True, raise_error=True):
        """Validates a new user object before saving it in the database.
        Checks if a password is present unles must_provide_password is False.
        Checks if the username is unqiue unless the option username_is_unique is set to False.
        If the email column exists on the user object and the option email_is_unique is set to True,
        also checks if the email is unique.
        """
        ucol = self.options['username_column']
        emailcol = self.options['email_column']
        username = getattr(user, ucol, None)
        email = getattr(user, emailcol, None)
        password = getattr(user, self.options["password_column"], None)

        if must_provide_password and not password:
            if raise_error:
                raise SignupValidationFailedException("password_missing")
            return False
        if ucol != emailcol and self.options["must_provide_username"] and not username:
            if flash_messages and self.options["must_provide_username_error_message"]:
                flash(self.options["must_provide_username_error_message"], "error")
            if raise_error:
                raise SignupValidationFailedException("username_missing")
            return False
        if ucol != emailcol and self.options["username_is_unique"]:
            if self.query_model.filter_by(**dict([(ucol, username)])).count() > 0:
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
            if self.query_model.filter_by(**dict([(emailcol, email)])).count() > 0:
                if flash_messages and self.options["signup_email_exists_message"]:
                    flash(self.options["signup_email_exists_message"], "error")
                if raise_error:
                    raise SignupValidationFailedException("email_exists")
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
            current_app.features.emails.send(to_email, "users/welcome.txt", user=user)

    @action(default_option="user")
    def gen_reset_password_token(self, user=None, send_email=None):
        """Generates a reset password token and optionnaly (default to yes) send the reset
        password email
        """
        if not user and "form" in current_context.data and request.method == "POST":
            form = current_context.data.form
            ucol = self.options["username_column"]
            user = self.query_model.filter_by(**dict([(ucol, form[ucol].data)])).first()

        if not user:
            raise InvalidOptionError("Invalid user in 'reset_password_token' action")

        token = self.generate_user_token(user, salt="password-reset")
        self.reset_password_token_signal.send(self, user=user, token=token)
        if (send_email is None and self.options["send_reset_password_email"]) or send_email:
            to_email = getattr(user, self.options["email_column"])
            current_app.features.emails.send(to_email, "users/reset_password.txt", user=user, token=token)
        return token

    @command("send-reset-password")
    def send_reset_password_command(self, username, send_email=True):
        user = self.get_by_username(username)
        if not user:
            raise Exception("User '%s' not found" % username)
        token = self.gen_reset_password_token(user, send_email)
        command.echo(url_for("users.reset_password", token=token, _external=True))

    @action(default_option="token")
    def reset_password(self, token=None, login_user=None):
        """Resets the password of the user identified by the token
        """
        ucol = self.options['username_column']
        pwcol = self.options['password_column']
        if not token:
            if "token" in request.view_args:
                token = request.view_args["token"]
            elif "token" in request.values:
                token = request.values["token"]
            else:
                raise OptionMissingError(("Missing 'token' option or 'token' view arg "
                                          "or 'token' GET paramater in 'reset_password' action"))

        user = self.load_user_from_token(token, salt="password-reset", max_age=self.options["reset_password_ttl"])
        if user is None:
            if self.options["reset_password_token_error_message"]:
                flash(self.options["reset_password_error_message"], "error")
            current_context.exit(trigger_action_group="reset_password_failed")

        self.update_password_from_form(user)
        self.reset_password_signal.send(self, user=user)
        if (login_user is None and self.options["login_user_on_reset_password"]) or login_user:
            login.login_user(user)
        return user

    @command("reset-password")
    def reset_password_command(self, username, password):
        user = self.get_by_username(username)
        if not user:
            raise Exception("User '%s' not found" % username)
        self.update_password(user, password)
        current_app.features.models.save(user)

    @action("update_user_password", default_option="user")
    def update_password_from_form(self, user=None, form=None):
        """Updates the user password using a form
        """
        user = user or current_user
        pwcol = self.options['password_column']
        pwcurrentcol = pwcol + "_current"
        pwconfirmcol = pwcol + "_confirm"
        if not form and "form" in current_context.data and request.method == "POST":
            form = current_context.data.form
        elif not form:
            raise OptionMissingError("Missing a form in 'update_user_password' action")

        password = form[pwcol].data
        if pwcurrentcol in form and not self.bcrypt.check_password_hash(getattr(user, pwcol), form[pwcurrentcol].data):
            if self.options["update_password_error_message"]:
                flash(self.options["update_password_error_message"], "error")
            current_context.exit(trigger_action_group="reset_password_current_mismatch")
        self.check_password_confirm(form, "reset_password_confirm_mismatch")

        self.update_password(user, password)
        current_app.features.models.save(user)
        self.update_user_password_signal.send(self, user=user)

    @action()
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
        if not self.bcrypt.check_password_hash(getattr(user, pwcol), password):
            current_context.exit(trigger_action_group="password_mismatch")

    @action("check_user_unique_attr", default_option="name")
    def check_unique_attr(self, name, value=None, user=None, form=None, flash_msg=None):
        """Checks that an attribute of the current user is unique amongst all users.
        If no value is provided, the current form will be used.
        """
        idcol = self.model.__primary_key_column__
        user = user or current_user
        if value is None:
            form = form or current_context.data.get("form")
            if not form:
                raise OptionMissingError("Missing 'value' option or form in 'check_user_unique_attr' action")
            value = form[name].data

        q = self.query_model.filter(self.query_model.op(name, "=", value),\
                                    self.query_model.op(idcol, "!=", getattr(user, idcol)))
        if q.count() > 0:
            if flash_msg is None:
                flash_msg = "The %s is already in use" % name
            if flash_msg:
                flash(flash_msg, "error")
            current_context.exit(trigger_action_group="user_attr_not_unique")

    def oauth_login(self, provider, id_column, id, attrs, defaults):
        """Execute a login via oauth. If no user exists, oauth_signup() will be called
        """
        user = self.query_model.filter_by(**dict([(id_column, id)])).first()
        redirect_url = request.args.get('next') or url_for(self.options["redirect_after_login"])
        if current_user.is_authenticated():
            if user and user != current_user:
                if self.options["oauth_user_already_exists_message"]:
                    flash(self.options["oauth_user_already_exists_message"].format(provider=provider), "error")
                return redirect(redirect_url)
            if provider not in current_user.auth_providers:
                current_user.auth_providers.append(provider)
            current_app.features.models.save(current_user, **attrs)
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
        user = self.get_by_username(username)
        if not user:
            raise Exception("User '%s' not found" % username)
        command.echo(user.for_json())