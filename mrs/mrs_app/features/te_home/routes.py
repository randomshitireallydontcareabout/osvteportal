"""Test Engineering section entry point.

The visible TE navigation is provided by isolated feature packages. This route
keeps the original /te URL working and forwards the user to the first TE tab
the account is authorized to open.
"""
from flask import Blueprint, redirect

bp = Blueprint("te_home", __name__)


def register(app):
    if bp.name in app.blueprints:
        return
    core = __import__(app.import_name, fromlist=["section_required", "first_allowed_url"])

    @bp.get("/te")
    @core.section_required("te")
    def index():
        return redirect(core.first_allowed_url())

    app.register_blueprint(bp)
