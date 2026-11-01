"""persist SIEM delivery results

Revision ID: 0f136de7e2a1
Revises: 49c00a864010
Create Date: 2026-11-01

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0f136de7e2a1"
down_revision: Union[str, Sequence[str], None] = "49c00a864010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "integration_deliveries",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("batch_key", sa.String(length=64), nullable=False),
        sa.Column("integration", sa.String(length=24), nullable=False),
        sa.Column("record_type", sa.String(length=32), nullable=False),
        sa.Column("record_ids", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("error", sa.String(length=240), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("batch_key", name="uq_integration_delivery_batch_key"),
    )
    op.create_index(
        op.f("ix_integration_deliveries_batch_key"),
        "integration_deliveries",
        ["batch_key"],
        unique=False,
    )
    op.create_index(
        op.f("ix_integration_deliveries_created_at"),
        "integration_deliveries",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        op.f("ix_integration_deliveries_integration"),
        "integration_deliveries",
        ["integration"],
        unique=False,
    )
    op.create_index(
        op.f("ix_integration_deliveries_record_type"),
        "integration_deliveries",
        ["record_type"],
        unique=False,
    )
    op.create_index(
        op.f("ix_integration_deliveries_status"),
        "integration_deliveries",
        ["status"],
        unique=False,
    )
    op.create_index(
        op.f("ix_integration_deliveries_updated_at"),
        "integration_deliveries",
        ["updated_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_integration_deliveries_updated_at"), table_name="integration_deliveries")
    op.drop_index(op.f("ix_integration_deliveries_status"), table_name="integration_deliveries")
    op.drop_index(op.f("ix_integration_deliveries_record_type"), table_name="integration_deliveries")
    op.drop_index(op.f("ix_integration_deliveries_integration"), table_name="integration_deliveries")
    op.drop_index(op.f("ix_integration_deliveries_created_at"), table_name="integration_deliveries")
    op.drop_index(op.f("ix_integration_deliveries_batch_key"), table_name="integration_deliveries")
    op.drop_table("integration_deliveries")
