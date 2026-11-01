# Isolated features

Create one folder per feature. Its `__init__.py` must expose `register(app)`. Use a Flask Blueprint with a unique name and URL prefix. Keep feature templates beneath that feature folder and feature data tables separate.
