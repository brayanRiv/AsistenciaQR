from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt as pyjwt  # Importar con alias para evitar conflictos
import datetime
from functools import wraps

app = Flask(__name__)

# Configuración de la base de datos
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fe4d61b2ad570a03abc4910e9d10362f1e3a24ce334d8b2')

db = SQLAlchemy(app)
migrate = Migrate(app, db)


# Modelo de Usuario
class Usuario(db.Model):
    __tablename__ = 'usuarios'
    user_id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(50), nullable=False)

    # Relaciones
    asistencias = db.relationship('Asistencia', backref='usuario', lazy=True)
    reportes = db.relationship('Reporte', backref='usuario', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# Modelo de Aula
class Aula(db.Model):
    __tablename__ = 'aulas'
    aula_id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    ubicacion = db.Column(db.String(150), nullable=False)

    # Relaciones
    asistencias = db.relationship('Asistencia', backref='aula', lazy=True)
    sesiones_qr = db.relationship('SesionQR', backref='aula', lazy=True)


# Modelo de Asistencia
class Asistencia(db.Model):
    __tablename__ = 'asistencias'
    asistencia_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.user_id'), nullable=False)
    aula_id = db.Column(db.Integer, db.ForeignKey('aulas.aula_id'), nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.datetime.now(datetime.UTC), nullable=False)
    estado = db.Column(db.String(50), nullable=False)  # Por ejemplo: 'Presente', 'Ausente'


# Modelo de SesionQR
class SesionQR(db.Model):
    __tablename__ = 'sesiones_qr'
    sesion_id = db.Column(db.Integer, primary_key=True)
    aula_id = db.Column(db.Integer, db.ForeignKey('aulas.aula_id'), nullable=False)
    codigo_qr = db.Column(db.String(255), unique=True, nullable=False)
    fecha_inicio = db.Column(db.DateTime, nullable=False)
    fecha_fin = db.Column(db.DateTime, nullable=False)


# Modelo de Reporte
class Reporte(db.Model):
    __tablename__ = 'reportes'
    reporte_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('usuarios.user_id'), nullable=False)
    titulo = db.Column(db.String(150), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    fecha = db.Column(db.DateTime, default=datetime.datetime.now(datetime.UTC), nullable=False)


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


@app.route('/registro', methods=['POST'])
def registro():
    try:
        data = request.get_json()
        nombre = data.get('nombre')
        apellido = data.get('apellido')
        email = data.get('email')
        password = data.get('password')
        rol = data.get('rol')

        if not all([nombre, apellido, email, password, rol]):
            return jsonify({'mensaje': 'Faltan datos!'}), 400

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

        return jsonify({'mensaje': 'Usuario registrado exitosamente!'}), 201
    except Exception as e:
        app.logger.error(f"Error en registro: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')

        if not all([email, password]):
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        usuario = Usuario.query.filter_by(email=email).first()
        if not usuario or not usuario.check_password(password):
            return jsonify({'mensaje': 'Credenciales inválidas!'}), 401

        token = pyjwt.encode({
            'user_id': usuario.user_id,
            'exp': datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token': token}), 200
    except Exception as e:
        app.logger.error(f"Error en login: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500


@app.route('/protegido', methods=['GET'])
@token_requerido
def protegido(current_user):
    return jsonify({'mensaje': f'Hola {current_user.nombre}, tienes acceso a esta ruta protegida!'}), 200


# Ruta para registrar una asistencia
@app.route('/asistencia', methods=['POST'])
@token_requerido
def registrar_asistencia(current_user):
    try:
        data = request.get_json()
        aula_id = data.get('aula_id')
        estado = data.get('estado')  # Por ejemplo: 'Presente'

        if not all([aula_id, estado]):
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        aula = Aula.query.get(aula_id)
        if not aula:
            return jsonify({'mensaje': 'Aula no encontrada!'}), 404

        nueva_asistencia = Asistencia(
            user_id=current_user.user_id,
            aula_id=aula_id,
            estado=estado
        )
        db.session.add(nueva_asistencia)
        db.session.commit()

        return jsonify({'mensaje': 'Asistencia registrada exitosamente!'}), 201
    except Exception as e:
        app.logger.error(f"Error en registrar asistencia: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500


# Ruta para obtener el leaderboard
@app.route('/leaderboard', methods=['GET'])
def obtener_leaderboard():
    try:
        # Consulta para contar asistencias por usuario
        leaderboard = db.session.query(
            Usuario.user_id,
            Usuario.nombre,
            Usuario.apellido,
            db.func.count(Asistencia.asistencia_id).label('total_asistencias')
        ).join(Asistencia).group_by(Usuario.user_id).order_by(db.desc('total_asistencias')).limit(10).all()

        resultado = []
        for entry in leaderboard:
            resultado.append({
                'user_id': entry.user_id,
                'nombre': entry.nombre,
                'apellido': entry.apellido,
                'total_asistencias': entry.total_asistencias
            })
        return jsonify({'leaderboard': resultado}), 200
    except Exception as e:
        app.logger.error(f"Error en obtener leaderboard: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500


# Rutas adicionales para manejar Aulas, SesionesQR y Reportes

# Ruta para crear una Aula
@app.route('/aulas', methods=['POST'])
@token_requerido
def crear_aula(current_user):
    try:
        data = request.get_json()
        nombre = data.get('nombre')
        ubicacion = data.get('ubicacion')

        if not all([nombre, ubicacion]):
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        nueva_aula = Aula(
            nombre=nombre,
            ubicacion=ubicacion
        )
        db.session.add(nueva_aula)
        db.session.commit()

        return jsonify({'mensaje': 'Aula creada exitosamente!', 'aula_id': nueva_aula.aula_id}), 201
    except Exception as e:
        app.logger.error(f"Error en crear aula: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500


# Ruta para obtener todas las Aulas
@app.route('/aulas', methods=['GET'])
def obtener_aulas():
    try:
        aulas = Aula.query.all()
        resultado = []
        for aula in aulas:
            resultado.append({
                'aula_id': aula.aula_id,
                'nombre': aula.nombre,
                'ubicacion': aula.ubicacion
            })
        return jsonify({'aulas': resultado}), 200
    except Exception as e:
        app.logger.error(f"Error en obtener aulas: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500


# Ruta para crear una Sesión QR
@app.route('/sesiones_qr', methods=['POST'])
@token_requerido
def crear_sesion_qr(current_user):
    try:
        data = request.get_json()
        aula_id = data.get('aula_id')
        codigo_qr = data.get('codigo_qr')
        fecha_inicio = data.get('fecha_inicio')  # Formato ISO 8601
        fecha_fin = data.get('fecha_fin')  # Formato ISO 8601

        if not all([aula_id, codigo_qr, fecha_inicio, fecha_fin]):
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        aula = Aula.query.get(aula_id)
        if not aula:
            return jsonify({'mensaje': 'Aula no encontrada!'}), 404

        # Validar formato de fechas
        try:
            fecha_inicio_dt = datetime.datetime.fromisoformat(fecha_inicio)
            fecha_fin_dt = datetime.datetime.fromisoformat(fecha_fin)
        except ValueError:
            return jsonify({'mensaje': 'Formato de fecha inválido!'}), 400

        nueva_sesion = SesionQR(
            aula_id=aula_id,
            codigo_qr=codigo_qr,
            fecha_inicio=fecha_inicio_dt,
            fecha_fin=fecha_fin_dt
        )
        db.session.add(nueva_sesion)
        db.session.commit()

        return jsonify({'mensaje': 'Sesión QR creada exitosamente!', 'sesion_id': nueva_sesion.sesion_id}), 201
    except Exception as e:
        app.logger.error(f"Error en crear sesión QR: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500


# Ruta para obtener todas las Sesiones QR
@app.route('/sesiones_qr', methods=['GET'])
def obtener_sesiones_qr():
    try:
        sesiones = SesionQR.query.all()
        resultado = []
        for sesion in sesiones:
            resultado.append({
                'sesion_id': sesion.sesion_id,
                'aula_id': sesion.aula_id,
                'codigo_qr': sesion.codigo_qr,
                'fecha_inicio': sesion.fecha_inicio.isoformat(),
                'fecha_fin': sesion.fecha_fin.isoformat()
            })
        return jsonify({'sesiones_qr': resultado}), 200
    except Exception as e:
        app.logger.error(f"Error en obtener sesiones QR: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500


# Ruta para crear un Reporte
@app.route('/reportes', methods=['POST'])
@token_requerido
def crear_reporte(current_user):
    try:
        data = request.get_json()
        titulo = data.get('titulo')
        descripcion = data.get('descripcion')

        if not all([titulo, descripcion]):
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        nuevo_reporte = Reporte(
            user_id=current_user.user_id,
            titulo=titulo,
            descripcion=descripcion
        )
        db.session.add(nuevo_reporte)
        db.session.commit()

        return jsonify({'mensaje': 'Reporte creado exitosamente!', 'reporte_id': nuevo_reporte.reporte_id}), 201
    except Exception as e:
        app.logger.error(f"Error en crear reporte: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500


# Ruta para obtener los Reportes de un Usuario
@app.route('/reportes', methods=['GET'])
@token_requerido
def obtener_reportes(current_user):
    try:
        reportes = Reporte.query.filter_by(user_id=current_user.user_id).all()
        resultado = []
        for reporte in reportes:
            resultado.append({
                'reporte_id': reporte.reporte_id,
                'titulo': reporte.titulo,
                'descripcion': reporte.descripcion,
                'fecha': reporte.fecha.isoformat()
            })
        return jsonify({'reportes': resultado}), 200
    except Exception as e:
        app.logger.error(f"Error en obtener reportes: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500


if __name__ == '__main__':
    app.run(debug=True)
