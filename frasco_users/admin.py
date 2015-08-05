from frasco_admin import AdminBlueprint
from frasco import current_app, current_context, abort, request, redirect, url_for
from frasco_models.admin import create_model_admin_blueprint
from frasco_forms.form import wtfields
import inflection


def create_admin_blueprint(users):
    ucol = users.options['username_column']
    ecol = users.options['email_column']

    list_columns = [ucol]
    form_fields = [ucol]
    search_query_default_field = [ucol]
    if ucol != ecol:
        list_columns.append(ecol)
        form_fields.append(ecol)
        search_query_default_field.append(ecol)
    list_columns.extend([
        ('signup_at', 'Signup date'),
        ('last_login_at', 'Last login date')])
    form_fields.append(('password', wtfields.PasswordField()))

    bp = create_model_admin_blueprint("users", __name__, users.model, title="Users", menu="Users",
        icon="fa-users", with_create=False, can_create=True, with_edit=False, can_edit=True,
        search_query_default_field=search_query_default_field, list_columns=list_columns,
        form_fields=form_fields)

    @bp.view("/create", template="admin/models_default/create.html", methods=['GET', 'POST'])
    def create():
        form = bp.get_form_class()()
        current_context['form'] = form
        if form.validate_on_submit():
            user = users.signup(form=form, login_user=False)
            return redirect(url_for('.edit', id=user.id))

    @bp.view("/<id>", template="admin/models_default/edit.html", methods=['GET', 'POST'])
    def edit(id):
        user = users.query.get_or_404(id)
        form = bp.get_form_class()(obj=user)
        current_context['obj'] = user
        current_context['admin_section_title'] = "Edit user #%s" % user.id
        current_context['form'] = form
        current_context['edit_actions'] = [
            ('Reset password', '.reset_password', {}),
            ('Delete user', '.delete', {'style': 'danger'})
        ]
        if form.validate_on_submit():
            users.update_user_from_form(user, form)

    @bp.route("/<id>/reset-password")
    def reset_password(id):
        user = users.query.get_or_404(id)
        users.gen_reset_password_token(user)
        return redirect(url_for('.edit', id=id))

    return bp