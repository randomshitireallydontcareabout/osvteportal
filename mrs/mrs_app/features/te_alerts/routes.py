"""Isolated Test Engineering feature: Alerts."""
from flask import Blueprint, render_template

bp = Blueprint("te_alerts", __name__, template_folder="templates")

def register(app):
    if bp.name in app.blueprints:
        return
    core = __import__(app.import_name, fromlist=["section_required", "te_permission_required"])

    @bp.get("/te/alerts")
    @core.section_required("te")
    @core.te_permission_required("te_alerts")
    def index():
        return render_template("te_alerts/index.html")

    app.register_blueprint(bp)
