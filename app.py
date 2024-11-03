from dotenv import load_dotenv
load_dotenv()

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt as pyjwt  # Importar con alias para evitar conflictos
from datetime import datetime, timezone, timedelta
from functools import wraps

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
    aulas = db.relationship('Aula', backref='docente', lazy=True)

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
    hora_entrada = db.Column(db.Time, nullable=False)
    hora_salida = db.Column(db.Time)

# Modelo de SesionesQR
class SesionQR(db.Model):
    __tablename__ = 'sesionesqr'
    sesion_id = db.Column(db.Integer, primary_key=True)
    codigo_qr = db.Column(db.String(255), unique=True, nullable=False)
    aula_id = db.Column(db.Integer, db.ForeignKey('aulas.aula_id'), nullable=False)
    fecha_sesion = db.Column(db.Date, nullable=False)
    hora_inicio = db.Column(db.Time, nullable=False)
    hora_fin = db.Column(db.Time, nullable=False)

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
def obtener_aula(aula_id, current_user):
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
def actualizar_aula(aula_id, current_user):
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

        if not all([aula_id, fecha_sesion, hora_inicio, hora_fin]):
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        # Verificar que el aula existe y pertenece al docente
        aula = Aula.query.get(aula_id)
        if not aula:
            return jsonify({'mensaje': 'Aula no encontrada!'}), 404

        if aula.docente_id != current_user.user_id:
            return jsonify({'mensaje': 'No tienes permiso para crear una sesión en esta aula!'}), 403

        # Generar un código QR único
        codigo_qr = generate_unique_qr_code()

        nueva_sesion_qr = SesionQR(
            codigo_qr=codigo_qr,
            aula_id=aula_id,
            fecha_sesion=datetime.strptime(fecha_sesion, '%Y-%m-%d').date(),
            hora_inicio=datetime.strptime(hora_inicio, '%H:%M:%S').time(),
            hora_fin=datetime.strptime(hora_fin, '%H:%M:%S').time()
        )
        db.session.add(nueva_sesion_qr)
        db.session.commit()

        return jsonify({'mensaje': 'Sesión QR creada exitosamente!', 'codigo_qr': codigo_qr}), 201
    except Exception as e:
        app.logger.error(f"Error al crear sesión QR: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

def generate_unique_qr_code():
    import uuid
    return str(uuid.uuid4())

# Ruta para registrar asistencia
@app.route('/asistencias', methods=['POST'])
@token_requerido
def registrar_asistencia(current_user):
    # Solo estudiantes pueden registrar asistencia
    if current_user.rol != 'estudiante':
        return jsonify({'mensaje': 'No tienes permiso para realizar esta acción!'}), 403

    try:
        data = request.get_json()
        codigo_qr = data.get('codigo_qr')
        if not codigo_qr:
            return jsonify({'mensaje': 'Faltan datos!'}), 400

        # Verificar que el código QR corresponde a una SesionQR activa
        sesion_qr = SesionQR.query.filter_by(codigo_qr=codigo_qr).first()
        if not sesion_qr:
            return jsonify({'mensaje': 'Código QR inválido!'}), 400

        # Verificar que la sesión está activa
        current_time = datetime.now(timezone.utc).time()
        if not (sesion_qr.hora_inicio <= current_time <= sesion_qr.hora_fin):
            return jsonify({'mensaje': 'La sesión no está activa!'}), 400

        # Verificar si el estudiante ya registró asistencia para esta sesión
        fecha_hoy = datetime.now(timezone.utc).date()
        asistencia = Asistencia.query.filter_by(
            user_id=current_user.user_id,
            aula_id=sesion_qr.aula_id,
            fecha_asistencia=fecha_hoy
        ).first()
        if asistencia:
            return jsonify({'mensaje': 'Ya has registrado tu asistencia para esta sesión!'}), 400

        # Registrar asistencia
        nueva_asistencia = Asistencia(
            user_id=current_user.user_id,
            aula_id=sesion_qr.aula_id,
            fecha_asistencia=fecha_hoy,
            hora_entrada=current_time
        )
        db.session.add(nueva_asistencia)

        # Actualizar leaderboard
        leaderboard_entry = Leaderboard.query.filter_by(user_id=current_user.user_id).first()
        if not leaderboard_entry:
            leaderboard_entry = Leaderboard(
                user_id=current_user.user_id,
                puntos=1,
                fecha_actualizacion=datetime.now(timezone.utc)
            )
            db.session.add(leaderboard_entry)
        else:
            leaderboard_entry.puntos += 1
            leaderboard_entry.fecha_actualizacion = datetime.now(timezone.utc)

        db.session.commit()
        return jsonify({'mensaje': 'Asistencia registrada exitosamente!'}), 201
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
            fecha_inicio = datetime.strptime(fecha_inicio, '%Y-%m-%d').date()
            query = query.filter(Asistencia.fecha_asistencia >= fecha_inicio)

        if fecha_fin:
            fecha_fin = datetime.strptime(fecha_fin, '%Y-%m-%d').date()
            query = query.filter(Asistencia.fecha_asistencia <= fecha_fin)

        asistencias = query.all()
        resultado = []
        for asistencia in asistencias:
            asistencia_data = {
                'asistencia_id': asistencia.asistencia_id,
                'user_id': asistencia.user_id,
                'aula_id': asistencia.aula_id,
                'fecha_asistencia': str(asistencia.fecha_asistencia),
                'hora_entrada': str(asistencia.hora_entrada),
                'hora_salida': str(asistencia.hora_salida) if asistencia.hora_salida else None
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
                'fecha_actualizacion': str(entry.fecha_actualizacion)
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
        # Obtener total de estudiantes
        total_estudiantes = Usuario.query.filter_by(rol='estudiante').count()
        if total_estudiantes == 0:
            return jsonify({'mensaje': 'No hay estudiantes registrados!'}), 400

        # Rango de fechas de la última semana
        fecha_fin = datetime.now(timezone.utc).date()
        fecha_inicio = fecha_fin - timedelta(days=7)

        aulas = Aula.query.all()
        for aula in aulas:
            # Contar asistencias en el aula en la última semana
            asistencias_count = Asistencia.query.filter(
                Asistencia.aula_id == aula.aula_id,
                Asistencia.fecha_asistencia >= fecha_inicio,
                Asistencia.fecha_asistencia <= fecha_fin
            ).count()

            # Calcular porcentaje de asistencia
            # Suponiendo que hay una clase diaria
            dias_clase = 7
            asistencia_total_posible = total_estudiantes * dias_clase
            if asistencia_total_posible == 0:
                continue

            porcentaje_asistencia = (asistencias_count / asistencia_total_posible) * 100

            if porcentaje_asistencia < 50:
                # Generar alerta
                descripcion = f'La asistencia en el aula {aula.nombre} ha caído por debajo del 50% en la última semana.'
                alerta_existente = Alerta.query.filter_by(
                    tipo='Asistencia Baja',
                    descripcion=descripcion
                ).first()
                if not alerta_existente:
                    nueva_alerta = Alerta(
                        tipo='Asistencia Baja',
                        descripcion=descripcion
                    )
                    db.session.add(nueva_alerta)
        db.session.commit()
        return jsonify({'mensaje': 'Alertas generadas exitosamente!'}), 200
    except Exception as e:
        app.logger.error(f"Error al generar alertas: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

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
                'fecha_creacion': str(alerta.fecha_creacion)
            }
            resultado.append(alerta_data)
        return jsonify({'alertas': resultado}), 200
    except Exception as e:
        app.logger.error(f"Error al obtener alertas: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

if __name__ == '__main__':
    app.run(debug=True)
