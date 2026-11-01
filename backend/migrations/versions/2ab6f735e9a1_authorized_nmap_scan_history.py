"""persist authorized Nmap scan history

Revision ID: 2ab6f735e9a1
Revises: 0f136de7e2a1
Create Date: 2026-11-02

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "2ab6f735e9a1"
down_revision: Union[str, Sequence[str], None] = "0f136de7e2a1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "nmap_scans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("target", sa.String(length=45), nullable=False),
        sa.Column("profile", sa.String(length=24), nullable=False),
        sa.Column("scan_type", sa.String(length=24), nullable=False),
        sa.Column("ports", sa.JSON(), nullable=False),
        sa.Column("service_detection", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("initiated_by", sa.String(length=64), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.String(length=240), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_nmap_scans_initiated_by"), "nmap_scans", ["initiated_by"], unique=False)
    op.create_index(op.f("ix_nmap_scans_started_at"), "nmap_scans", ["started_at"], unique=False)
    op.create_index(op.f("ix_nmap_scans_status"), "nmap_scans", ["status"], unique=False)
    op.create_index(op.f("ix_nmap_scans_target"), "nmap_scans", ["target"], unique=False)


def downgrade() -> None:
    op.drop_index(op.f("ix_nmap_scans_target"), table_name="nmap_scans")
    op.drop_index(op.f("ix_nmap_scans_status"), table_name="nmap_scans")
    op.drop_index(op.f("ix_nmap_scans_started_at"), table_name="nmap_scans")
    op.drop_index(op.f("ix_nmap_scans_initiated_by"), table_name="nmap_scans")
    op.drop_table("nmap_scans")
