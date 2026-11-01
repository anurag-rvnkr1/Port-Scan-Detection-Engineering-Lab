"""add managed Zeek and Suricata log sensors

Revision ID: 3c42d52ef091
Revises: 2ab6f735e9a1
Create Date: 2026-11-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "3c42d52ef091"
down_revision: Union[str, Sequence[str], None] = "2ab6f735e9a1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "sensors",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=80), nullable=False),
        sa.Column("sensor_type", sa.String(length=16), nullable=False),
        sa.Column("log_path", sa.String(length=1024), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("cursor_offset", sa.BigInteger(), nullable=False),
        sa.Column("file_identity", sa.String(length=128), nullable=True),
        sa.Column("pending_line", sa.Text(), nullable=False),
        sa.Column("zeek_header", sa.Text(), nullable=True),
        sa.Column("processed_records", sa.Integer(), nullable=False),
        sa.Column("parse_error_count", sa.Integer(), nullable=False),
        sa.Column("last_error", sa.String(length=240), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_sensors_created_at"), "sensors", ["created_at"], unique=False)
    op.create_index(op.f("ix_sensors_name"), "sensors", ["name"], unique=True)
    op.create_index(op.f("ix_sensors_sensor_type"), "sensors", ["sensor_type"], unique=False)
    op.create_index(op.f("ix_sensors_status"), "sensors", ["status"], unique=False)
    op.create_index(op.f("ix_sensors_updated_at"), "sensors", ["updated_at"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_sensors_updated_at"), table_name="sensors")
    op.drop_index(op.f("ix_sensors_status"), table_name="sensors")
    op.drop_index(op.f("ix_sensors_sensor_type"), table_name="sensors")
    op.drop_index(op.f("ix_sensors_name"), table_name="sensors")
    op.drop_index(op.f("ix_sensors_created_at"), table_name="sensors")
    op.drop_table("sensors")
