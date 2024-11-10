# app/schemas.py

from marshmallow import Schema, fields, validate

class RegistroSchema(Schema):
    nombre = fields.String(required=True, validate=validate.Length(min=1))
    apellido = fields.String(required=True, validate=validate.Length(min=1))
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=8))

class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=8))

class CrearUsuarioSchema(Schema):
    nombre = fields.String(required=True, validate=validate.Length(min=1))
    apellido = fields.String(required=True, validate=validate.Length(min=1))
    email = fields.Email(required=True)
    password = fields.String(required=True, validate=validate.Length(min=8))
    rol = fields.String(required=True, validate=validate.OneOf(['docente', 'director']))
