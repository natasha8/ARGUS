"""store the OWASP Top 10:2025 category on findings

Revision ID: 003_finding_owasp_web
Revises: 002_endpoint_security
Create Date: 2026-10-18

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003_finding_owasp_web"
down_revision: Union[str, Sequence[str], None] = "002_endpoint_security"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("owasp_web", sa.String(length=16), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "owasp_web")
