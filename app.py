from flask import Flask, request, jsonify
from flask_migrate import Migrate
from functools import wraps
import os
import jwt as pyjwt
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
app = Flask(__name__)

# Configuración de la base de datos
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'tu_secreto')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Modelo de Usuario
class Usuario(db.Model):
    __tablename__ = 'usuario'
    user_id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(50), nullable=False)
    fecha_registro = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ultimo_login = db.Column(db.DateTime)

    asistencias = db.relationship('Asistencia', backref='usuario', lazy=True)
    reportes = db.relationship('Reporte', backref='usuario', lazy=True)
    leaderboard = db.relationship('Leaderboard', backref='usuario', uselist=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Modelo de Aulas
class Aula(db.Model):
    __tablename__ = 'aulas'
    aula_id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    turno = db.Column(db.String(50), nullable=False)

    asistencias = db.relationship('Asistencia', backref='aula', lazy=True)
    sesiones_qr = db.relationship('SesionQR', backref='aula', lazy=True)

# Modelo de Asistencias
class Asistencia(db.Model):
    __tablename__ = 'asistencias'
    asistencia_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Usuarios.user_id'), nullable=False)
    aula_id = db.Column(db.Integer, db.ForeignKey('Aulas.aula_id'), nullable=False)
    fecha_asistencia = db.Column(db.Date, nullable=False)
    hora_entrada = db.Column(db.Time, nullable=False)
    hora_salida = db.Column(db.Time)

# Modelo de SesionesQR
class SesionQR(db.Model):
    __tablename__ = 'sesionesqr'
    sesion_id = db.Column(db.Integer, primary_key=True)
    codigo_qr = db.Column(db.String(255), unique=True, nullable=False)
    aula_id = db.Column(db.Integer, db.ForeignKey('Aulas.aula_id'), nullable=False)
    fecha_sesion = db.Column(db.Date, nullable=False)
    hora_inicio = db.Column(db.Time, nullable=False)
    hora_fin = db.Column(db.Time, nullable=False)

# Modelo de Reportes
class Reporte(db.Model):
    __tablename__ = 'reportes'
    reporte_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Usuarios.user_id'), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    fecha_reporte = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Modelo de Leaderboard
class Leaderboard(db.Model):
    __tablename__ = 'leaderboard'
    leaderboard_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Usuarios.user_id'), unique=True, nullable=False)
    puntos = db.Column(db.Integer, default=0)
    fecha_actualizacion = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Decorador para rutas protegidas
def token_requerido(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'mensaje': 'Token está ausente!'}), 401
        try:
            data = pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Usuario.query.filter_by(user_id=data['user_id']).first()
        except pyjwt.ExpiredSignatureError:
            return jsonify({'mensaje': 'Token expirado!'}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({'mensaje': 'Token inválido!'}), 401
        except Exception as e:
            app.logger.error(f"Error al decodificar el token: {str(e)}")
            return jsonify({'mensaje': 'Error interno del servidor!'}), 500
        return f(current_user, *args, **kwargs)
    return decorated

# Rutas CRUD para Aulas
@app.route('/', methods=['GET'])
def index():
    return jsonify({'mensaje': 'Bienvenido a la API de Asistencia QR!'}), 200

@app.route('/aulas', methods=['POST'])
@token_requerido
def crear_aula(current_user):
    try:
        data = request.get_json()
        nombre = data.get('nombre')
        turno = data.get('turno')

        if not all([nombre, turno]):
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        if turno not in ['Mañana', 'Tarde', 'Noche']:
            return jsonify({'mensaje': 'Turno inválido!'}), 400

        nueva_aula = Aula(nombre=nombre, turno=turno)
        db.session.add(nueva_aula)
        db.session.commit()

        return jsonify({'mensaje': 'Aula creada exitosamente!'}), 201
    except Exception as e:
        app.logger.error(f"Error al crear aula: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

@app.route('/aulas', methods=['GET'])
@token_requerido
def obtener_aulas(current_user):
    try:
        aulas = Aula.query.all()
        resultado = []
        for aula in aulas:
            aula_data = {
                'aula_id': aula.aula_id,
                'nombre': aula.nombre,
                'turno': aula.turno
            }
            resultado.append(aula_data)
        return jsonify({'aulas': resultado}), 200
    except Exception as e:
        app.logger.error(f"Error al obtener aulas: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

@app.route('/aulas/<int:aula_id>', methods=['GET'])
@token_requerido
def obtener_aula(aula_id, current_user):
    try:
        aula = Aula.query.get(aula_id)
        if not aula:
            return jsonify({'mensaje': 'Aula no encontrada!'}), 404

        aula_data = {
            'aula_id': aula.aula_id,
            'nombre': aula.nombre,
            'turno': aula.turno
        }
        return jsonify({'aula': aula_data}), 200
    except Exception as e:
        app.logger.error(f"Error al obtener aula: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

@app.route('/aulas/<int:aula_id>', methods=['PUT'])
@token_requerido
def actualizar_aula(aula_id, current_user):
    try:
        aula = Aula.query.get(aula_id)
        if not aula:
            return jsonify({'mensaje': 'Aula no encontrada!'}), 404

        data = request.get_json()
        nombre = data.get('nombre')
        turno = data.get('turno')

        if nombre:
            aula.nombre = nombre
        if turno:
            if turno not in ['Mañana', 'Tarde', 'Noche']:
                return jsonify({'mensaje': 'Turno inválido!'}), 400
            aula.turno = turno

        db.session.commit()
        return jsonify({'mensaje': 'Aula actualizada exitosamente!'}), 200
    except Exception as e:
        app.logger.error(f"Error al actualizar aula: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

@app.route('/aulas/<int:aula_id>', methods=['DELETE'])
@token_requerido
def eliminar_aula(aula_id, current_user):
    try:
        aula = Aula.query.get(aula_id)
        if not aula:
            return jsonify({'mensaje': 'Aula no encontrada!'}), 404

        db.session.delete(aula)
        db.session.commit()
        return jsonify({'mensaje': 'Aula eliminada exitosamente!'}), 200
    except Exception as e:
        app.logger.error(f"Error al eliminar aula: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500
