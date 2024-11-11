import hashlib
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from io import BytesIO
from flask import current_app
from app import db
import segno
from PIL import Image, ImageDraw
import os

from app.models import Asistencia


def generar_codigo_qr_unico_estudiante():
    codigo_qr = secrets.token_urlsafe(32)
    return codigo_qr

def verificar_sesion_activa(sesion_qr, current_datetime):
    current_time = current_datetime.time()
    current_date = current_datetime.date()

    if current_date != sesion_qr.fecha_sesion:
        return {'mensaje': 'La sesión no está activa hoy!'}, 400

    if not (sesion_qr.hora_inicio <= current_time <= sesion_qr.hora_fin):
        return {'mensaje': 'La sesión no está activa en este momento!'}, 400

    return None, None  # No hay error

def generar_codigo_qr_sesion_director(sesion_id):
    """
    Genera un código QR único para una sesión de director basada en el ID de la sesión y una clave secreta.
    """
    data = f"director-sesion-{sesion_id}-{current_app.config['SECRET_KEY']}"
    codigo_qr = hashlib.sha256(data.encode()).hexdigest()
    return codigo_qr


def generar_codigo_qr_dinamico(entity_id, entity_type):
    """
    Genera un código QR dinámico basado en el ID de la entidad y su tipo.

    :param entity_id: ID de la entidad (sesion_id para estudiantes, user_id para docentes)
    :param entity_type: Tipo de entidad ('sesion' o 'docente')
    :return: Código QR generado como una cadena hexadecimal
    """
    lima_timezone = timezone(timedelta(hours=-5))  # UTC-5
    current_time = datetime.now(lima_timezone)
    current_minute = current_time.strftime('%Y%m%d%H%M')  # AñoMesDíaHoraMinuto

    # Concatenamos entity_type, entity_id, current_minute y SECRET_KEY para generar el hash
    data = f"{entity_type}-{entity_id}-{current_minute}-{current_app.config['SECRET_KEY']}"
    codigo_qr = hashlib.sha256(data.encode()).hexdigest()
    return codigo_qr


def generar_codigo_qr_dinamico_estudiante(sesion_id):
    return generar_codigo_qr_dinamico(sesion_id, 'sesion')

def generar_codigo_qr_dinamico_docente(user_id):
    return generar_codigo_qr_dinamico(user_id, 'docente')

def generar_imagen_qr_con_logo(codigo_qr):
    # Crear QR Code con segno
    qr = segno.make(codigo_qr, error='h')  # Alto nivel de corrección de errores

    # Guardar el QR a BytesIO
    buffered = BytesIO()
    qr.save(buffered, kind='png', scale=10)
    qr_img = Image.open(buffered).convert('RGB')

    # Cargar el logo
    logo_path = os.path.join('static', 'logo.png')
    if not os.path.exists(logo_path):
        raise FileNotFoundError(f"Logo no encontrado en la ruta: {logo_path}")
    logo = Image.open(logo_path)

    # Calcular el tamaño del logo (20% del tamaño del QR)
    qr_width, qr_height = qr_img.size
    logo_size = int(qr_width * 0.2)
    try:
        # Intentar usar Resampling.LANCZOS, si no está disponible, usar ANTIALIAS
        logo = logo.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
    except AttributeError:
        logo = logo.resize((logo_size, logo_size), Image.Resampling.LANCZOS)

    # Crear una máscara circular para el logo
    mask = Image.new('L', (logo_size, logo_size), 0)
    draw = ImageDraw.Draw(mask)
    draw.ellipse((0, 0, logo_size, logo_size), fill=255)
    logo.putalpha(mask)

    # Opcional: Agregar un borde blanco alrededor del logo para mejor visibilidad
    border_size = int(logo_size * 0.05)  # 5% del tamaño del logo
    bordered_logo_size = logo_size + 2 * border_size
    bordered_logo = Image.new('RGBA', (bordered_logo_size, bordered_logo_size), (255, 255, 255, 0))
    bordered_logo.paste(logo, (border_size, border_size), logo)

    # Posicionar el logo en el centro del QR
    pos = ((qr_width - bordered_logo_size) // 2, (qr_height - bordered_logo_size) // 2)
    qr_img.paste(bordered_logo, pos, bordered_logo)

    return qr_img

def obtener_nombre_dia_espanol(fecha):
    dias_semana = {
        0: 'LUNES',
        1: 'MARTES',
        2: 'MIÉRCOLES',
        3: 'JUEVES',
        4: 'VIERNES',
        5: 'SÁBADO',
        6: 'DOMINGO'
    }
    dia_semana = fecha.weekday()  # Devuelve un número de 0 (lunes) a 6 (domingo)
    return dias_semana.get(dia_semana, '')


def registrar_asistencia_estudiante(estudiante_id, sesion_qr, current_datetime):
    # Verificar si el estudiante ya registró asistencia
    asistencia_existente = Asistencia.query.filter_by(
        user_id=estudiante_id,
        aula_id=sesion_qr.aula_id,
        fecha_asistencia=current_datetime.date()
    ).first()

    if asistencia_existente:
        return {'mensaje': 'El estudiante ya tiene registrada su asistencia para esta sesión!'}, 400

    # Registrar la asistencia
    estado = 'asistió'
    hora_llegada = current_datetime.time()

    # Determinar si el estudiante llegó tarde
    hora_entrada_permitida = (datetime.combine(current_datetime.date(), sesion_qr.hora_inicio) +
                              timedelta(minutes=sesion_qr.tolerancia_minutos)).time()

    if hora_llegada > hora_entrada_permitida:
        estado = 'tardanza'

    nueva_asistencia = Asistencia(
        user_id=estudiante_id,
        aula_id=sesion_qr.aula_id,
        fecha_asistencia=current_datetime.date(),
        hora_entrada=hora_llegada,
        estado=estado
    )
    db.session.add(nueva_asistencia)
    db.session.commit()

    return {'mensaje': 'Asistencia registrada exitosamente!', 'estado': estado}, 201

def generate_unique_qr_code():
    return str(uuid.uuid4())

import jwt
import uuid
from datetime import datetime, timedelta

def generar_token(usuario_id, clave_secreta):
    payload = {
        'user_id': usuario_id,
        'exp': datetime.utcnow() + timedelta(days=1),
        'jti': str(uuid.uuid4())  # Añade un identificador único al token
    }
    token = jwt.encode(payload, clave_secreta, algorithm='HS256')
    return token
