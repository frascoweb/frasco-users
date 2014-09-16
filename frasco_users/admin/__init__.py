from frasco_admin import AdminBlueprint


bp = AdminBlueprint("admin_users", __name__, url_prefix="/users", template_folder="templates")


@bp.view("/", template="admin/users/index.html", admin_title="Users", admin_menu="Users", admin_menu_icon="users")
def index():
    pass