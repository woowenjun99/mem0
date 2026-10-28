"""Track refresh-token families for logout and replay revocation.

Revision ID: 007
Revises: 006
"""

from alembic import op
import sqlalchemy as sa

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "refresh_sessions",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("user_id", sa.Uuid(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.add_column("refresh_token_jtis", sa.Column("session_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_refresh_jti_session", "refresh_token_jtis", "refresh_sessions", ["session_id"], ["id"], ondelete="CASCADE"
    )
    op.create_index("ix_refresh_token_jtis_session_id", "refresh_token_jtis", ["session_id"])


def downgrade() -> None:
    op.drop_index("ix_refresh_token_jtis_session_id", table_name="refresh_token_jtis")
    op.drop_constraint("fk_refresh_jti_session", "refresh_token_jtis", type_="foreignkey")
    op.drop_column("refresh_token_jtis", "session_id")
    op.drop_table("refresh_sessions")
