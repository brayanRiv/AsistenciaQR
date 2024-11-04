from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt as pyjwt  # Importar con alias para evitar conflictos
from datetime import datetime, timezone, timedelta, time
from functools import wraps
from io import BytesIO
from sqlalchemy.exc import SQLAlchemyError
import csv
import hashlib

app = Flask(__name__)

# Configuración de la base de datos
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fe4d61b2ad570a03abc4910e9d10362f1e3a24ce334d8b22')

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Modelos

class Usuario(db.Model):
    __tablename__ = 'usuario'
    user_id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(50), nullable=False)
    fecha_registro = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    ultimo_login = db.Column(db.DateTime)

    asistencias = db.relationship('Asistencia', backref='usuario', lazy=True)
    reportes = db.relationship('Reporte', backref='usuario', lazy=True)
    leaderboard = db.relationship('Leaderboard', backref='usuario', uselist=False)
    aulas = db.relationship('Aula', backref='docente', lazy=True, foreign_keys='Aula.docente_id')

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
    docente_id = db.Column(db.Integer, db.ForeignKey('usuario.user_id'), nullable=True)

    asistencias = db.relationship('Asistencia', backref='aula', lazy=True)
    sesiones_qr = db.relationship('SesionQR', backref='aula', lazy=True)

# Modelo de Asistencias
class Asistencia(db.Model):
    __tablename__ = 'asistencias'
    asistencia_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('usuario.user_id'), nullable=False, index=True)
    aula_id = db.Column(db.Integer, db.ForeignKey('aulas.aula_id'), nullable=False, index=True)
    fecha_asistencia = db.Column(db.Date, nullable=False, index=True)
    hora_entrada = db.Column(db.Time)
    hora_salida = db.Column(db.Time)
    estado = db.Column(db.String(50), nullable=False)

# Modelo de SesionesQR
class SesionQR(db.Model):
    __tablename__ = 'sesionesqr'
    sesion_id = db.Column(db.Integer, primary_key=True)
    aula_id = db.Column(db.Integer, db.ForeignKey('aulas.aula_id'), nullable=False)
    docente_id = db.Column(db.Integer, db.ForeignKey('usuario.user_id'), nullable=False)
    fecha_sesion = db.Column(db.Date, nullable=False)
    hora_inicio = db.Column(db.Time, nullable=False)
    hora_fin = db.Column(db.Time, nullable=False)
    tolerancia_minutos = db.Column(db.Integer, default=0)


# Modelo de Reportes
class Reporte(db.Model):
    __tablename__ = 'reportes'
    reporte_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('usuario.user_id'), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    fecha_reporte = db.Column(db.DateTime, default=datetime.now(timezone.utc))

# Modelo de Leaderboard
class Leaderboard(db.Model):
    __tablename__ = 'leaderboard'
    leaderboard_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('usuario.user_id'), unique=True, nullable=False)
    puntos = db.Column(db.Integer, default=0, index=True)
    fecha_actualizacion = db.Column(db.DateTime, default=datetime.now(timezone.utc))

# Modelo de Alertas
class Alerta(db.Model):
    __tablename__ = 'alertas'
    alerta_id = db.Column(db.Integer, primary_key=True)
    tipo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text, nullable=False)
    fecha_creacion = db.Column(db.DateTime, default=datetime.now(timezone.utc))

# Decorador para rutas protegidas
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
            data = pyjwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Usuario.query.filter_by(user_id=data['user_id']).first()
            if not current_user:
                return jsonify({'mensaje': 'Usuario no encontrado!'}), 401
        except pyjwt.ExpiredSignatureError:
            return jsonify({'mensaje': 'Token expirado!'}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({'mensaje': 'Token inválido!'}), 401
        except Exception as e:
            app.logger.error(f"Error al decodificar el token: {str(e)}")
            return jsonify({'mensaje': 'Error interno del servidor!'}), 500
        return f(current_user, *args, **kwargs)
    return decorated

# Decorador para verificar roles
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated(current_user, *args, **kwargs):
            if current_user.rol not in roles:
                return jsonify({'mensaje': 'No tienes permiso para realizar esta acción!'}), 403
            return f(current_user, *args, **kwargs)
        return decorated
    return decorator

# Ruta para la raíz '/'
@app.route('/', methods=['GET'])
def index():
    return jsonify({'mensaje': 'Bienvenido a la API de Asistencia QR!'}), 200

# Ruta de registro
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

# Ruta de login
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
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({'token': token}), 200
    except Exception as e:
        app.logger.error(f"Error en login: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

# Ruta protegida
@app.route('/protegido', methods=['GET'])
@token_requerido
def protegido(current_user):
    return jsonify({'mensaje': f'Hola {current_user.nombre}, tienes acceso a esta ruta protegida!'}), 200

# Rutas CRUD para Aulas
@app.route('/aulas', methods=['POST'])
@token_requerido
@role_required(['admin'])
def crear_aula(current_user):
    try:
        data = request.get_json()
        nombre = data.get('nombre')
        turno = data.get('turno')
        docente_id = data.get('docente_id')

        if not all([nombre, turno]):
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        if turno not in ['Mañana', 'Tarde', 'Noche']:
            return jsonify({'mensaje': 'Turno inválido!'}), 400

        nueva_aula = Aula(nombre=nombre, turno=turno, docente_id=docente_id)
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
                'turno': aula.turno,
                'docente_id': aula.docente_id
            }
            resultado.append(aula_data)
        return jsonify({'aulas': resultado}), 200
    except Exception as e:
        app.logger.error(f"Error al obtener aulas: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

@app.route('/aulas/<int:aula_id>', methods=['GET'])
@token_requerido
def obtener_aula(current_user, aula_id):
    try:
        aula = Aula.query.get(aula_id)
        if not aula:
            return jsonify({'mensaje': 'Aula no encontrada!'}), 404

        aula_data = {
            'aula_id': aula.aula_id,
            'nombre': aula.nombre,
            'turno': aula.turno,
            'docente_id': aula.docente_id
        }
        return jsonify({'aula': aula_data}), 200
    except Exception as e:
        app.logger.error(f"Error al obtener aula: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

@app.route('/aulas/<int:aula_id>', methods=['PUT'])
@token_requerido
@role_required(['admin'])
def actualizar_aula(current_user, aula_id):
    try:
        aula = Aula.query.get(aula_id)
        if not aula:
            return jsonify({'mensaje': 'Aula no encontrada!'}), 404

        data = request.get_json()
        nombre = data.get('nombre')
        turno = data.get('turno')
        docente_id = data.get('docente_id')

        if nombre:
            aula.nombre = nombre
        if turno:
            if turno not in ['Mañana', 'Tarde', 'Noche']:
                return jsonify({'mensaje': 'Turno inválido!'}), 400
            aula.turno = turno
        if docente_id is not None:
            aula.docente_id = docente_id

        db.session.commit()
        return jsonify({'mensaje': 'Aula actualizada exitosamente!'}), 200
    except Exception as e:
        app.logger.error(f"Error al actualizar aula: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

@app.route('/aulas/<int:aula_id>', methods=['DELETE'])
@token_requerido
@role_required(['admin'])
def eliminar_aula(current_user, aula_id):
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

# Ruta para crear Sesión QR
@app.route('/sesionqr', methods=['POST'])
@token_requerido
@role_required(['docente'])
def crear_sesion_qr(current_user):
    try:
        data = request.get_json()
        aula_id = data.get('aula_id')
        fecha_sesion = data.get('fecha_sesion')
        hora_inicio = data.get('hora_inicio')
        hora_fin = data.get('hora_fin')
        tolerancia_minutos = data.get('tolerancia_minutos', 0)

        if not all([aula_id, fecha_sesion, hora_inicio, hora_fin]):
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        # Verificar que el aula existe
        aula = Aula.query.get(aula_id)
        if not aula:
            return jsonify({'mensaje': 'Aula no encontrada!'}), 404

        # Verificar que el aula tiene un docente asignado
        if not aula.docente_id:
            return jsonify({'mensaje': 'El aula no tiene un docente asignado!'}), 400

        # Verificar que el docente actual es el asignado al aula
        if aula.docente_id != current_user.user_id:
            return jsonify({'mensaje': 'No tienes permiso para crear una sesión en esta aula!'}), 403

        # Convertir fechas y horas
        try:
            fecha_sesion_dt = datetime.strptime(fecha_sesion, '%Y-%m-%d').date()
            hora_inicio_tm = datetime.strptime(hora_inicio, '%H:%M:%S').time()
            hora_fin_tm = datetime.strptime(hora_fin, '%H:%M:%S').time()
        except ValueError as e:
            return jsonify({'mensaje': f'Formato de fecha u hora inválido: {str(e)}'}), 400

        # Verificar que hora_inicio es anterior a hora_fin
        if hora_inicio_tm >= hora_fin_tm:
            return jsonify({'mensaje': 'La hora de inicio debe ser anterior a la hora de fin!'}), 400

        nueva_sesion_qr = SesionQR(
            aula_id=aula_id,
            docente_id=current_user.user_id,
            fecha_sesion=fecha_sesion_dt,
            hora_inicio=hora_inicio_tm,
            hora_fin=hora_fin_tm,
            tolerancia_minutos=tolerancia_minutos
        )
        db.session.add(nueva_sesion_qr)
        db.session.commit()

        return jsonify({'mensaje': 'Sesión QR creada exitosamente!', 'sesion_id': nueva_sesion_qr.sesion_id}), 201
    except SQLAlchemyError as e:
        db.session.rollback()
        app.logger.error(f"Error de base de datos al crear sesión QR: {str(e)}")
        return jsonify({'mensaje': f'Error de base de datos: {str(e)}'}), 500
    except Exception as e:
        app.logger.error(f"Error al crear sesión QR: {str(e)}")
        return jsonify({'mensaje': f'Error interno del servidor: {str(e)}'}), 500

def generate_unique_qr_code():
    import uuid
    return str(uuid.uuid4())

def generar_codigo_qr_dinamico(sesion_id):
    # Usamos la hora actual (minuto actual) para generar un código que cambia cada minuto
    lima_timezone = timezone(timedelta(hours=-5))  # UTC-5
    current_time = datetime.now(lima_timezone)
    current_minute = current_time.strftime('%Y%m%d%H%M')  # AñoMesDíaHoraMinuto

    # Concatenamos sesion_id, current_minute y SECRET_KEY para generar el hash
    data = f"{sesion_id}-{current_minute}-{app.config['SECRET_KEY']}"
    codigo_qr = hashlib.sha256(data.encode()).hexdigest()
    return codigo_qr


@app.route('/sesionqr/<int:sesion_id>/codigo', methods=['GET'])
@token_requerido
@role_required(['docente', 'estudiante'])
def obtener_codigo_qr(current_user, sesion_id):
    try:
        # Obtener la sesión
        sesion = SesionQR.query.get(sesion_id)
        if not sesion:
            return jsonify({'mensaje': 'Sesión no encontrada!'}), 404

        # Verificar que la sesión está activa
        lima_timezone = timezone(timedelta(hours=-5))  # UTC-5
        current_time = datetime.now(lima_timezone).time()

        if not (sesion.hora_inicio <= current_time <= sesion.hora_fin):
            return jsonify({'mensaje': 'La sesión no está activa!'}), 400

        # Generar el código QR dinámico
        codigo_qr = generar_codigo_qr_dinamico(sesion_id)

        return jsonify({'codigo_qr': codigo_qr}), 200
    except Exception as e:
        app.logger.error(f"Error al obtener código QR: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500



# Ruta para registrar asistencia
@app.route('/asistencias', methods=['POST'])
@token_requerido
def registrar_asistencia(current_user):
    if current_user.rol != 'estudiante':
        return jsonify({'mensaje': 'No tienes permiso para realizar esta acción!'}), 403

    try:
        data = request.get_json()
        sesion_id = data.get('sesion_id')
        codigo_qr_provided = data.get('codigo_qr')
        if not all([sesion_id, codigo_qr_provided]):
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        # Obtener la sesión
        sesion_qr = SesionQR.query.get(sesion_id)
        if not sesion_qr:
            return jsonify({'mensaje': 'Sesión no encontrada!'}), 404

        # Verificar que la sesión está activa
        lima_timezone = timezone(timedelta(hours=-5))  # UTC-5
        current_datetime = datetime.now(lima_timezone)
        current_time = current_datetime.time()
        current_date = current_datetime.date()

        if current_date != sesion_qr.fecha_sesion:
            return jsonify({'mensaje': 'La sesión no está activa hoy!'}), 400

        if not (sesion_qr.hora_inicio <= current_time <= sesion_qr.hora_fin):
            return jsonify({'mensaje': 'La sesión no está activa en este momento!'}), 400

        # Generar el código QR actual
        codigo_qr_actual = generar_codigo_qr_dinamico(sesion_id)

        # Verificar si el código proporcionado coincide
        if codigo_qr_provided != codigo_qr_actual:
            return jsonify({'mensaje': 'Código QR inválido o expirado!'}), 400

        # Verificar si el estudiante ya registró asistencia
        asistencia_existente = Asistencia.query.filter_by(
            user_id=current_user.user_id,
            aula_id=sesion_qr.aula_id,
            fecha_asistencia=current_date
        ).first()

        if asistencia_existente:
            return jsonify({'mensaje': 'Ya has registrado tu asistencia para esta sesión!'}), 400

        # Registrar la asistencia
        estado = 'asistió'
        hora_llegada = current_time

        # Determinar si el estudiante llegó tarde
        hora_entrada_permitida = (datetime.combine(current_date, sesion_qr.hora_inicio) +
                                  timedelta(minutes=sesion_qr.tolerancia_minutos)).time()

        if hora_llegada > hora_entrada_permitida:
            estado = 'tardanza'

        nueva_asistencia = Asistencia(
            user_id=current_user.user_id,
            aula_id=sesion_qr.aula_id,
            fecha_asistencia=current_date,
            hora_entrada=hora_llegada,
            estado=estado
        )
        db.session.add(nueva_asistencia)
        db.session.commit()

        return jsonify({'mensaje': 'Asistencia registrada exitosamente!', 'estado': estado}), 201

    except Exception as e:
        app.logger.error(f"Error al registrar asistencia: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

# Ruta para obtener asistencias con filtros avanzados
@app.route('/asistencias', methods=['GET'])
@token_requerido
def obtener_asistencias(current_user):
    try:
        # Obtener parámetros de filtro
        aula_id = request.args.get('aula_id', type=int)
        docente_id = request.args.get('docente_id', type=int)
        fecha_inicio = request.args.get('fecha_inicio')
        fecha_fin = request.args.get('fecha_fin')

        query = Asistencia.query

        if aula_id:
            query = query.filter_by(aula_id=aula_id)

        if docente_id:
            # Filtrar asistencias por aulas del docente
            query = query.join(Aula).filter(Aula.docente_id == docente_id)

        if fecha_inicio:
            fecha_inicio = datetime.strptime(fecha_inicio, '%d/%m/%Y').date()
            query = query.filter(Asistencia.fecha_asistencia >= fecha_inicio)

        if fecha_fin:
            fecha_fin = datetime.strptime(fecha_fin, '%d/%m/%Y').date()
            query = query.filter(Asistencia.fecha_asistencia <= fecha_fin)

        asistencias = query.all()
        resultado = []
        for asistencia in asistencias:
            asistencia_data = {
                'asistencia_id': asistencia.asistencia_id,
                'user_id': asistencia.user_id,
                'aula_id': asistencia.aula_id,
                'fecha_asistencia': asistencia.fecha_asistencia.strftime('%d/%m/%Y'),
                'hora_entrada': asistencia.hora_entrada.strftime('%H:%M:%S') if asistencia.hora_entrada else None,
                'hora_salida': asistencia.hora_salida.strftime('%H:%M:%S') if asistencia.hora_salida else None,
                'estado': asistencia.estado
            }
            resultado.append(asistencia_data)
        return jsonify({'asistencias': resultado}), 200
    except Exception as e:
        app.logger.error(f"Error al obtener asistencias: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

# Ruta para obtener el leaderboard
@app.route('/leaderboard', methods=['GET'])
@token_requerido
def obtener_leaderboard(current_user):
    try:
        leaderboard = Leaderboard.query.join(Usuario).order_by(Leaderboard.puntos.desc()).all()
        resultado = []
        for entry in leaderboard:
            usuario = entry.usuario
            entry_data = {
                'user_id': entry.user_id,
                'nombre': usuario.nombre,
                'apellido': usuario.apellido,
                'puntos': entry.puntos,
                'fecha_actualizacion': entry.fecha_actualizacion.strftime('%d/%m/%Y %H:%M:%S')
            }
            resultado.append(entry_data)
        return jsonify({'leaderboard': resultado}), 200
    except Exception as e:
        app.logger.error(f"Error al obtener leaderboard: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

# Ruta para generar alertas
@app.route('/alertas/generar', methods=['POST'])
@token_requerido
@role_required(['admin'])
def generar_alertas(current_user):
    try:
        generar_alertas_asistencias()
        return jsonify({'mensaje': 'Alertas generadas exitosamente!'}), 200
    except Exception as e:
        app.logger.error(f"Error al generar alertas: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

def generar_alertas_asistencias():
    estudiantes = Usuario.query.filter_by(rol='estudiante').all()
    lima_timezone = timezone(timedelta(hours=-5))
    fecha_hoy = datetime.now(lima_timezone).date()
    fecha_inicio = fecha_hoy - timedelta(days=7)

    for estudiante in estudiantes:
        asistencias_tardanzas = Asistencia.query.filter(
            Asistencia.user_id == estudiante.user_id,
            Asistencia.fecha_asistencia >= fecha_inicio,
            Asistencia.estado == 'tardanza'
        ).count()

        if asistencias_tardanzas >= 3:
            descripcion = f"El estudiante {estudiante.nombre} {estudiante.apellido} ha llegado tarde {asistencias_tardanzas} veces en la última semana."
            alerta_existente = Alerta.query.filter_by(descripcion=descripcion).first()
            if not alerta_existente:
                nueva_alerta = Alerta(
                    tipo='Tardanzas Repetitivas',
                    descripcion=descripcion
                )
                db.session.add(nueva_alerta)
    db.session.commit()

# Ruta para obtener alertas
@app.route('/alertas', methods=['GET'])
@token_requerido
@role_required(['admin'])
def obtener_alertas(current_user):
    try:
        alertas = Alerta.query.order_by(Alerta.fecha_creacion.desc()).all()
        resultado = []
        for alerta in alertas:
            alerta_data = {
                'alerta_id': alerta.alerta_id,
                'tipo': alerta.tipo,
                'descripcion': alerta.descripcion,
                'fecha_creacion': alerta.fecha_creacion.strftime('%d/%m/%Y %H:%M:%S')
            }
            resultado.append(alerta_data)
        return jsonify({'alertas': resultado}), 200
    except Exception as e:
        app.logger.error(f"Error al obtener alertas: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

# Ruta para exportar asistencias
@app.route('/asistencias/exportar', methods=['GET'])
@token_requerido
@role_required(['docente', 'admin'])
def exportar_asistencias(current_user):
    try:
        sesion_id = request.args.get('sesion_id', type=int)
        if not sesion_id:
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        # Obtener la sesión
        sesion_qr = SesionQR.query.get(sesion_id)
        if not sesion_qr:
            return jsonify({'mensaje': 'Sesión no encontrada!'}), 404

        # Verificar permisos
        if current_user.rol == 'docente' and sesion_qr.docente_id != current_user.user_id:
            return jsonify({'mensaje': 'No tienes permiso para exportar estas asistencias!'}), 403

        # Obtener las asistencias de la sesión
        asistencias = Asistencia.query.filter_by(
            aula_id=sesion_qr.aula_id,
            fecha_asistencia=sesion_qr.fecha_sesion
        ).all()

        # Crear el Excel
        from openpyxl import Workbook
        wb = Workbook()
        ws = wb.active
        ws.title = "Asistencias"

        # Escribir cabeceras
        ws.append(['APELLIDOS', 'NOMBRES', 'ESTADO', 'FECHA', 'HORA_ENTRADA'])

        for asistencia in asistencias:
            usuario = asistencia.usuario
            ws.append([
                usuario.apellido,
                usuario.nombre,
                asistencia.estado,
                asistencia.fecha_asistencia.strftime('%d/%m/%Y'),
                asistencia.hora_entrada.strftime('%H:%M:%S') if asistencia.hora_entrada else ''
            ])

        # Guardar en BytesIO
        output = BytesIO()
        wb.save(output)
        output.seek(0)

        filename = f"asistencias_sesion_{sesion_id}.xlsx"

        # Enviar el archivo con los headers correctos
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        app.logger.error(f"Error al exportar asistencias: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500


if __name__ == '__main__':
    app.run(debug=True)
