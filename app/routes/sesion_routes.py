from flask import Blueprint, request, jsonify, render_template, abort
from sqlalchemy.exc import SQLAlchemyError

from app.models import SesionQR, DirectorSesion, Aula
from app.utils.decorators import token_requerido, role_required
from app.utils.helpers import generar_codigo_qr_sesion_director, generar_codigo_qr_dinamico_docente, \
    generar_imagen_qr_con_logo, generar_codigo_qr_dinamico
from flask import current_app
from app import db
from datetime import datetime, timezone, timedelta
from io import BytesIO
import base64

sesion_bp = Blueprint('sesion_bp', __name__)

@sesion_bp.route('/director/sesion', methods=['POST'])
@token_requerido
@role_required(['director'])
def crear_sesion_director(current_user):
    try:
        lima_timezone = timezone(timedelta(hours=-5))  # UTC-5
        today = datetime.now(lima_timezone).date()

        # Verificar si ya existe una sesión para hoy
        sesion_existente = DirectorSesion.query.filter_by(fecha_sesion=today, activa=True).first()
        if sesion_existente:
            return jsonify({'mensaje': 'Ya existe una sesión activa para hoy!'}), 400

        nueva_sesion = DirectorSesion(fecha_sesion=today)
        db.session.add(nueva_sesion)
        db.session.commit()

        return jsonify({'mensaje': 'Sesión de director creada exitosamente!', 'sesion_id': nueva_sesion.sesion_id}), 201
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error al crear sesión de director: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500


@sesion_bp.route('/sesionqr', methods=['POST'])
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
        current_app.logger.error(f"Error de base de datos al crear sesión QR: {str(e)}")
        return jsonify({'mensaje': f'Error de base de datos: {str(e)}'}), 500
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error al crear sesión QR: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor.'}), 500

@sesion_bp.route('/director/sesion/<int:sesion_id>/codigo', methods=['GET'])
@token_requerido
@role_required(['director'])
def obtener_codigo_qr_sesion_director(current_user, sesion_id):
    try:
        # Obtener la sesión del director
        sesion = DirectorSesion.query.get(sesion_id)
        if not sesion:
            return jsonify({'mensaje': 'Sesión no encontrada!'}), 404

        # Verificar que la sesión pertenece al director actual
        # Asumiendo que hay una relación que asocia sesiones con directores
        # Si no existe, podrías necesitar agregarla en el modelo DirectorSesion
        # Por ejemplo, agregar un campo `director_id` en DirectorSesion
        # y verificar que sesion.director_id == current_user.user_id

        # Aquí se asume que tal relación existe
        # Si no, ajusta el código según tu modelo de datos

        # Generar el código QR para la sesión
        codigo_qr = generar_codigo_qr_sesion_director(sesion_id)

        return jsonify({
            'sesion_id': sesion.sesion_id,
            'codigo_qr': codigo_qr
        }), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error al obtener código QR de sesión del director: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

@sesion_bp.route('/sesionqr/<int:sesion_id>/codigo', methods=['GET'])
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
        codigo_qr = generar_codigo_qr_dinamico(sesion_id, 'sesion')

        return jsonify({'codigo_qr': codigo_qr}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error al obtener código QR: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500

@sesion_bp.route('/docente/asistencia/codigo/view', methods=['GET'])
@token_requerido
@role_required(['docente'])
def ver_codigo_qr_docente(current_user):
    try:
        # Verificar sesión activa del director
        lima_timezone = timezone(timedelta(hours=-5))
        current_date = datetime.now(lima_timezone).date()

        sesion_director = DirectorSesion.query.filter_by(fecha_sesion=current_date, activa=True).first()
        if not sesion_director:
            abort(404, description='No hay una sesión activa para hoy.')

        # Generar el código QR dinámico
        codigo_qr = generar_codigo_qr_dinamico_docente(current_user.user_id)

        # Crear imagen del código QR con logo
        qr_image = generar_imagen_qr_con_logo(codigo_qr)

        # Convertir imagen a base64
        buffered = BytesIO()
        qr_image.save(buffered, format="PNG")
        qr_code_b64 = base64.b64encode(buffered.getvalue()).decode()

        # Renderizar plantilla
        return render_template('qr_view.html', qr_code=qr_code_b64)

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error al mostrar código QR para docente: {str(e)}")
        abort(500)


@sesion_bp.route('/director/sesion/<int:sesion_id>/codigo/view', methods=['GET'])
@token_requerido
@role_required(['director'])
def ver_codigo_qr_sesion_director(current_user, sesion_id):
    try:
        # Obtener la sesión
        sesion = DirectorSesion.query.get(sesion_id)
        if not sesion or not sesion.activa:
            abort(404, description='Sesión no encontrada o inactiva.')

        # Generar el código QR dinámico
        codigo_qr = generar_codigo_qr_sesion_director(sesion_id)

        # Crear imagen del código QR con logo
        qr_image = generar_imagen_qr_con_logo(codigo_qr)

        # Convertir imagen a base64
        buffered = BytesIO()
        qr_image.save(buffered, format="PNG")
        qr_code_b64 = base64.b64encode(buffered.getvalue()).decode()

        # Renderizar plantilla
        return render_template('qr_view.html', qr_code=qr_code_b64)

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error al mostrar código QR para sesión del director: {str(e)}")
        abort(500)

@sesion_bp.route('/docente/asistencia/codigo', methods=['GET'])
@token_requerido
@role_required(['docente'])
def obtener_codigo_qr_docente(current_user):
    try:
        # Verificar que hay una sesión activa del director
        lima_timezone = timezone(timedelta(hours=-5))  # UTC-5
        current_date = datetime.now(lima_timezone).date()

        sesion_director = DirectorSesion.query.filter_by(fecha_sesion=current_date, activa=True).first()
        if not sesion_director:
            return jsonify({'mensaje': 'No hay una sesión activa para hoy!'}), 400

        # Generar el código QR dinámico para el docente
        codigo_qr = generar_codigo_qr_dinamico_docente(current_user.user_id)

        return jsonify({'codigo_qr': codigo_qr}), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error al obtener código QR para docente: {str(e)}")
        return jsonify({'mensaje': 'Error interno del servidor!'}), 500
