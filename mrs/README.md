# MRS Ticket Dashboard - Modular Package

Run `python test.py`. Existing data remains in the project `data` folder.

- `mrs_app/core.py`: preserved application behavior and routes
- `mrs_app/templates/`: one template per screen
- `mrs_app/static/`: shared CSS
- `mrs_app/features/`: isolated add-on feature packages

New features should be Flask Blueprints registered through `register(app)` in their own feature package.
