"""Isolated Test Engineering feature: KPI."""
from flask import Blueprint, render_template

bp = Blueprint("te_kpi", __name__, template_folder="templates")

def register(app):
    if bp.name in app.blueprints:
        return
    core = __import__(app.import_name, fromlist=["section_required", "te_permission_required"])

    @bp.get("/te/kpi")
    @core.section_required("te")
    @core.te_permission_required("te_kpi")
    def index():
        return render_template("te_kpi/index.html")

    app.register_blueprint(bp)
