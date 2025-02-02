import logging
from logging.handlers import RotatingFileHandler
from flask import Flask
from .config import Config
from .routes import main
from .extensions import db, migrate

def create_app():
    app = Flask(__name__)
    app.config.from_object('app.config.Config')
    app.config['SECRET_KEY'] = 'your_secret_key'  # Consider using an env variable
    app.config['UPLOAD_FOLDER'] = 'uploads'

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)

    with app.app_context():
        from . import routes
        db.create_all()

    # Register Blueprints AFTER initializing extensions
    from .routes import main
    app.register_blueprint(main)
    
    if not app.debug:
        handler = RotatingFileHandler('app.log', maxBytes=10240, backupCount=3)
        handler.setLevel(logging.ERROR)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        app.logger.addHandler(handler)

    return app
