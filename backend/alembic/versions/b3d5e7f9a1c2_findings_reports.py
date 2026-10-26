"""add findings and reports tables

Revision ID: b3d5e7f9a1c2
Revises: 7f2a1c9d4e10
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "b3d5e7f9a1c2"
down_revision: Union[str, Sequence[str], None] = "7f2a1c9d4e10"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.Column("service_id", sa.Integer(), nullable=True),
        sa.Column("key", sa.String(length=200), nullable=False),
        sa.Column("rule_id", sa.String(length=16), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("level", sa.String(length=10), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("factors", sa.JSON(), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("recommendation", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("accepted_comment", sa.String(length=1000), nullable=True),
        sa.Column("accepted_by", sa.Integer(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["accepted_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.ForeignKeyConstraint(["service_id"], ["services.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"], unique=False)
    op.create_index("ix_findings_host_id", "findings", ["host_id"], unique=False)
    op.create_index("ix_findings_key", "findings", ["key"], unique=False)
    op.create_index("ix_findings_level", "findings", ["level"], unique=False)
    op.create_table(
        "reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("generated_by", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("content", sa.LargeBinary(), nullable=False),
        sa.ForeignKeyConstraint(["generated_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_reports_scan_id", table_name="reports")
    op.drop_table("reports")
    op.drop_index("ix_findings_level", table_name="findings")
    op.drop_index("ix_findings_key", table_name="findings")
    op.drop_index("ix_findings_host_id", table_name="findings")
    op.drop_index("ix_findings_scan_id", table_name="findings")
    op.drop_table("findings")
