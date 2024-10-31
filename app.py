from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

# Configuración de la base de datos
database_url = os.environ.get('DATABASE_URL')
if database_url and database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Modelo de Usuario
class Usuario(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    nombre = db.Column(db.String(100), nullable=False)
    apellido = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    rol = db.Column(db.String(50), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Decorador para rutas protegidas
def token_requerido(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]
            except IndexError:
                return jsonify({'mensaje': 'Formato de token inválido!'}), 401
        if not token:
            return jsonify({'mensaje': 'Token está ausente!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = Usuario.query.filter_by(user_id=data['user_id']).first()
            if not current_user:
                return jsonify({'mensaje': 'Usuario no encontrado!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'mensaje': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'mensaje': 'Token inválido!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/registro', methods=['POST'])
def registro():
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

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({'mensaje': 'Faltan datos!'}), 400

    usuario = Usuario.query.filter_by(email=email).first()
    if not usuario or not usuario.check_password(password):
        return jsonify({'mensaje': 'Credenciales inválidas!'}), 401

    token = jwt.encode({
        'user_id': usuario.user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token': token}), 200

@app.route('/protegido', methods=['GET'])
@token_requerido
def protegido(current_user):
    return jsonify({'mensaje': f'Hola {current_user.nombre}, tienes acceso a esta ruta protegida!'}), 200

if __name__ == '__main__':
    app.run(debug=True)
