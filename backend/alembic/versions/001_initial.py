"""initial schema

Revision ID: 001_initial
Revises:
Create Date: 2026-10-18

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "001_initial"
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("target_base_url", sa.String(length=500), nullable=False),
        sa.Column("discovery_mode", sa.String(length=20), nullable=False),
        sa.Column("spec_document", sa.JSON(), nullable=True),
        sa.Column("manual_endpoints", sa.JSON(), nullable=True),
        sa.Column("auth_profiles", sa.JSON(), nullable=False),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("scope_confirmed", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_created_at", "scans", ["created_at"])
    op.create_table(
        "endpoints",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("method", sa.String(length=10), nullable=False),
        sa.Column("path", sa.String(length=500), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("request_body", sa.JSON(), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("auth_required", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_endpoints_scan_id", "endpoints", ["scan_id"])
    op.create_table(
        "findings",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("scan_id", sa.String(length=36), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("endpoint_id", sa.String(length=36), sa.ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True),
        sa.Column("endpoint_label", sa.String(length=520), nullable=True),
        sa.Column("category", sa.String(length=40), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("owasp_id", sa.String(length=40), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_category", "findings", ["category"])
    op.create_index("ix_findings_severity", "findings", ["severity"])
    op.create_index("ix_findings_status", "findings", ["status"])


def downgrade() -> None:
    op.drop_table("findings")
    op.drop_table("endpoints")
    op.drop_table("scans")
