"""
One-time schema migration runner for CGC Core.

Database.__init__() no longer runs its 7 schema-creation methods on every
boot (2026-09-04, see database.py's own header comment on that change --
mirrors the _create_rls_policies() fix from 2026-08-23) because every one
of those tables/indexes/policies already exists in production, and paying
53+ CREATE-TABLE/INDEX round trips on every Vercel cold start was pure
latency for work with nothing left to do.

Run this script instead, exactly once, whenever:
  - Bootstrapping a genuinely NEW environment (fresh DATABASE_URL, nothing
    created yet), or
  - You've added a new table to one of the six _create_*_schema() methods
    and need it created in an environment that already has the others, or
  - The RLS policies (_create_rls_policies) need to be recreated -- e.g.
    after adding a new tenant-scoped table.

Usage:
    DATABASE_URL=postgresql://... python scripts/run_schema_migrations.py

Safe to re-run: every statement these methods execute is CREATE TABLE/
INDEX/POLICY IF NOT EXISTS or an equivalent idempotent guard -- this was
already true before the speed fix, that's what made removing them from
__init__ safe in the first place.
"""

import logging
import sys

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("cgc.migrations")


def main() -> None:
    from app.Core.db.database import get_database

    db = get_database()
    if not db.use_postgres:
        logger.error(
            "No Postgres connection established (DATABASE_URL missing/unreachable) -- "
            "nothing to migrate against."
        )
        sys.exit(1)

    steps = [
        ("_create_tables", db._create_tables),
        ("_create_jla_schema", db._create_jla_schema),
        ("_create_pod_schema", db._create_pod_schema),
        ("_create_tco_schema", db._create_tco_schema),
        ("_create_guard_schema", db._create_guard_schema),
        ("_create_auth_schema", db._create_auth_schema),
        ("_create_rls_policies", db._create_rls_policies),
    ]

    for name, step in steps:
        logger.info("Running %s ...", name)
        step()
        logger.info("Done: %s", name)

    logger.info("All schema migrations complete.")


if __name__ == "__main__":
    main()
