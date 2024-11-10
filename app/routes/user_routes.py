from flask import Blueprint, request, jsonify, current_app
from app.models import Usuario
from app.schemas import CrearUsuarioSchema
from app.utils.decorators import token_requerido, role_required
from app import db
from marshmallow import ValidationError

user_bp = Blueprint('user_bp', __name__)

@user_bp.route('/usuarios', methods=['POST'])
@token_requerido
@role_required(['admin'])
def crear_usuario_por_admin(current_user):
    try:
        data = request.get_json()
        schema = CrearUsuarioSchema()
        result = schema.load(data)

        nombre = result['nombre']
        apellido = result['apellido']
        email = result['email']
        password = result['password']
        rol = result['rol']

        if Usuario.query.filter_by(email=email).first():
            return jsonify({'mensaje': 'El email ya está registrado!'}), 400

        nuevo_usuario = Usuario(
            nombre=nombre,
            apellido=apellido,
            email=email,
            rol=rol
        )
        nuevo_usuario.set_password(password)
        db.session.add(nuevo_usuario)
        db.session.commit()

        return jsonify({'mensaje': f'Usuario {rol} creado exitosamente!'}), 201
    except ValidationError as err:
        return jsonify({'mensaje': 'Datos inválidos!', 'errores': err.messages}), 400
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error al crear usuario por admin: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor.'}), 500

