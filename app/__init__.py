from dotenv import load_dotenv
load_dotenv()

import os
from flask import Flask, request, render_template
from flasgger import Swagger
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix

# Importar las extensiones
from .extensions import db, migrate, csrf, limiter

def create_app():
    app = Flask(__name__)

    # Configurar SECRET_KEY
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
    if not app.config['SECRET_KEY']:
        raise ValueError("No se ha establecido SECRET_KEY para la aplicación Flask")

    # Configuraciones adicionales
    app.config['WTF_CSRF_SECRET_KEY'] = app.config['SECRET_KEY']
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
    )

    # **Configuración de Flask-Limiter**
    redis_url = os.environ.get('REDIS_URL', 'memory://')
    app.config['RATELIMIT_STORAGE_URI'] = redis_url

    # Inicializar extensiones y middleware
    Talisman(app, content_security_policy=None)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    csrf.init_app(app)
    limiter.init_app(app)
    swagger = Swagger(app)

    # Configuración de registro en producción
    if not app.debug:
        import logging
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler('error.log', maxBytes=10240, backupCount=10)
        formatter = logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.ERROR)
        app.logger.addHandler(file_handler)

    # Establecer encabezados de seguridad
    @app.after_request
    def set_security_headers(response):
        response.headers['Content-Security-Policy'] = "default-src 'self'; img-src 'self' data:;"
        return response

    # Configuración de la base de datos
    database_url = os.environ.get('DATABASE_URL', 'sqlite:///local.db')
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Inicializar extensiones de base de datos
    db.init_app(app)
    migrate.init_app(app, db)

    # Evitar cacheo de respuestas sensibles
    @app.after_request
    def add_header(response):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response

    @app.before_request
    def csrf_protection():
        if request.endpoint in ['auth_bp.login', 'auth_bp.registro', 'auth_bp.logout'] or (request.endpoint and request.endpoint.startswith('api.')):
            csrf._disable_csrf = True
        else:
            csrf._disable_csrf = False

    # Registrar Blueprints
    from app.routes import register_routes
    register_routes(app)

    # Manejador de errores
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html'), 404

    return app
