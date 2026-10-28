"""Add account authentication versions without replacing refresh-session families.

Revision ID: 008
Revises: 007
"""

import sqlalchemy as sa
from alembic import op

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("auth_version", sa.Integer(), nullable=False, server_default="0"))
    # Existing JWTs lack auth_version and fail closed after upgrade.
    op.execute("DELETE FROM refresh_token_jtis")
    op.execute("DELETE FROM refresh_sessions")


def downgrade() -> None:
    op.drop_column("users", "auth_version")
