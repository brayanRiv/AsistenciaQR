from functools import wraps
from flask import request, jsonify, current_app
from app.models import Usuario, TokenRevocado
from app import db
import jwt as pyjwt

def token_requerido(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'mensaje': 'Token mal formado!'}), 401
        if not token:
            return jsonify({'mensaje': 'Token está ausente!'}), 401
        try:
            data = pyjwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            jti = data['jti']
            # Verificar si el token ha sido revocado
            token_revocado = TokenRevocado.query.filter_by(jti=jti).first()
            if token_revocado:
                return jsonify({'mensaje': 'Token revocado!'}), 401
            current_user = Usuario.query.filter_by(user_id=data['user_id']).first()
            if not current_user:
                return jsonify({'mensaje': 'Usuario no encontrado!'}), 401
        except pyjwt.ExpiredSignatureError:
            return jsonify({'mensaje': 'Token expirado!'}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({'mensaje': 'Token inválido!'}), 401
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error al decodificar el token: {str(e)}")
            return jsonify({'mensaje': 'Error interno del servidor!'}), 500
        return f(current_user, *args, **kwargs)
    return decorated

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated(current_user, *args, **kwargs):
            # Código del decorador...
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator
