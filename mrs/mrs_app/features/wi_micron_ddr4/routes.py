
from __future__ import annotations
import json
from pathlib import Path
from flask import Blueprint, abort, current_app, render_template, session

bp=Blueprint("wi_micron_ddr4",__name__,template_folder="templates",static_folder="static",static_url_path="/static/wi_micron_ddr4")
DATA=json.loads((Path(__file__).with_name("data.json")).read_text(encoding="utf-8"))

def register(app):
    if bp.name in app.blueprints: return
    core=__import__(app.import_name,fromlist=["user_can"])
    @bp.get("/tools/work-instructions/micron-ddr4")
    def index():
        if not session.get("user_id"): abort(401)
        section=session.get("active_section")
        allowed=(section=="osv" and core.user_can_section("osv") and core.user_can("tools")) or (section=="te" and core.user_can_section("te") and core.user_can_te("te_tools"))
        if not allowed: abort(403)
        return render_template("wi_micron_ddr4/index.html",component=DATA["component"],steps=DATA["steps"])
    app.register_blueprint(bp)
