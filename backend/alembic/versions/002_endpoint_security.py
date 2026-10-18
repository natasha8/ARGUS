"""store security schemes on endpoints

Revision ID: 002_endpoint_security
Revises: 001_initial
Create Date: 2026-10-18

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002_endpoint_security"
down_revision: Union[str, Sequence[str], None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("endpoints", sa.Column("security", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("endpoints", "security")
