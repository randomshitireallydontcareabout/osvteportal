from __future__ import annotations
import json
from pathlib import Path
from flask import Blueprint, abort, render_template, session
bp=Blueprint("wi_delta_psu",__name__,template_folder="templates",static_folder="static",static_url_path="/static/wi_delta_psu")
DATA_PATH=Path(__file__).with_name("data.json")
def register(app):
 if bp.name in app.blueprints:return
 core=__import__(app.import_name,fromlist=["user_can"])
 @bp.get("/tools/work-instructions/delta-psu")
 def index():
  if not session.get("user_id"):abort(401)
  section=session.get("active_section")
  allowed=(section=="osv" and core.user_can_section("osv") and core.user_can("tools")) or (section=="te" and core.user_can_section("te") and core.user_can_te("te_tools"))
  if not allowed:abort(403)
  data=json.loads(DATA_PATH.read_text(encoding="utf-8"))
  return render_template("wi_delta_psu/index.html",component=data["component"],steps=data["steps"])
 app.register_blueprint(bp)
