

def register_routes(app):
    from .main_routes import main_bp
    # Importar otros Blueprints
    from .auth_routes import auth_bp
    from .aula_routes import aula_bp
    from .asistencia_routes import asistencia_bp
    from .sesion_routes import sesion_bp
    # Registrar los Blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(aula_bp)
    app.register_blueprint(asistencia_bp)
    app.register_blueprint(sesion_bp)

