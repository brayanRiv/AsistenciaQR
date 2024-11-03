"""Migración inicial

Revision ID: 76b7b93d23e5
Revises: 
Create Date: 2024-11-03 11:38:06.373992

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '76b7b93d23e5'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('asistencias', schema=None) as batch_op:
        batch_op.add_column(sa.Column('estado', sa.String(length=50), nullable=False))
        batch_op.alter_column('hora_entrada',
               existing_type=postgresql.TIME(),
               nullable=True)

    with op.batch_alter_table('sesionesqr', schema=None) as batch_op:
        batch_op.add_column(sa.Column('docente_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('tolerancia_minutos', sa.Integer(), nullable=True))
        batch_op.create_foreign_key(None, 'usuario', ['docente_id'], ['user_id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sesionesqr', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('tolerancia_minutos')
        batch_op.drop_column('docente_id')

    with op.batch_alter_table('asistencias', schema=None) as batch_op:
        batch_op.alter_column('hora_entrada',
               existing_type=postgresql.TIME(),
               nullable=False)
        batch_op.drop_column('estado')

    # ### end Alembic commands ###
