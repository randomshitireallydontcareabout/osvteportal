from .routes import tester_db_bp
from .models import init_tester_db

def register(app):
    init_tester_db()
    app.register_blueprint(tester_db_bp)