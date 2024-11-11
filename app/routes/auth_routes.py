import uuid

from flask import Blueprint, request, jsonify, current_app
from app.models import Usuario, TokenRevocado
from app.schemas import LoginSchema, RegistroSchema
from app.extensions import db
from app import limiter
import jwt as pyjwt
from datetime import datetime, timezone, timedelta

from marshmallow import ValidationError

import re

from app.utils.decorators import token_requerido
from app.utils.helpers import generar_codigo_qr_unico_estudiante

auth_bp = Blueprint('auth_bp', __name__)

# Ya no necesitamos crear una nueva instancia de Limiter
# limiter = Limiter()  # Eliminar esta línea

@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    try:
        data = request.get_json()
        schema = LoginSchema()
        result = schema.load(data)

        email = result['email']
        password = result['password']

        usuario = Usuario.query.filter_by(email=email).first()
        if not usuario or not usuario.check_password(password):
            return jsonify({'mensaje': 'Credenciales inválidas!'}), 401

        # Actualizar el campo ultimo_login
        usuario.ultimo_login = datetime.now(timezone.utc)
        db.session.commit()

        # Generar un 'jti' único para el token
        jti = str(uuid.uuid4())

        token = pyjwt.encode({
            'user_id': usuario.user_id,
            'exp': datetime.now(timezone.utc) + timedelta(hours=24),
            'jti': jti
        }, current_app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token': token}), 200
    except ValidationError as err:
        return jsonify({'mensaje': 'Datos inválidos!', 'errores': err.messages}), 400
    except Exception as e:
        current_app.logger.error(f"Error en login: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor.'}), 500

@auth_bp.route('/registro', methods=['POST'])
@limiter.limit("5 per minute")
def registro():
    try:
        data = request.get_json()
        schema = RegistroSchema()
        result = schema.load(data)
        nombre = data.get('nombre')
        apellido = data.get('apellido')
        email = data.get('email')
        password = data.get('password')

        # Validar complejidad de la contraseña
        if len(password) < 8 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) \
                or not re.search(r"[0-9]", password) or not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            return jsonify({
                'mensaje': 'La contraseña debe tener al menos 8 caracteres, incluyendo mayúsculas, minúsculas, números y símbolos.'
            }), 400

        if not all([nombre, apellido, email, password]):
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        if Usuario.query.filter_by(email=email).first():
            return jsonify({'mensaje': 'El email ya está registrado!'}), 400

        codigo_qr = generar_codigo_qr_unico_estudiante()

        nuevo_usuario = Usuario(
            nombre=nombre,
            apellido=apellido,
            email=email,
            rol='estudiante',
            codigo_qr=codigo_qr
        )
        nuevo_usuario.set_password(password)
        db.session.add(nuevo_usuario)
        db.session.commit()

        return jsonify({'mensaje': 'Usuario registrado exitosamente!'}), 201
    except ValidationError as err:
        return jsonify({'mensaje': 'Datos inválidos!', 'errores': err.messages}), 400
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error en registro: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

@auth_bp.route('/logout', methods=['POST'])
@token_requerido
def logout():
    try:
        token = request.headers['Authorization'].split(" ")[1]
        jti = pyjwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])['jti']
        nuevo_token_revocado = TokenRevocado(jti=jti)
        db.session.add(nuevo_token_revocado)
        db.session.commit()
        return jsonify({'mensaje': 'Sesión cerrada exitosamente!'}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error en logout: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

