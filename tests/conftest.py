"""
Shared fixtures for CGC Core's test suite.

DB-backed tests need a real disposable Postgres (this project's real bugs
have all been concurrency/RLS/schema issues that only exist against a real
database -- mocking the DB would test nothing that has ever actually broken
here). Point TEST_DATABASE_URL at one; CI spins up a throwaway Postgres
service container for exactly this. Tests that need it skip cleanly if
none is reachable, rather than failing the whole run for a dev machine
with no local Postgres.
"""

import os
import uuid

import pytest

# Must happen before any test module imports app.Core.db.database --
# Database is a process-wide singleton, constructed on first use, so
# whatever DATABASE_URL is set to at that moment is what it uses for the
# rest of the process. Never point this at production.
os.environ["DATABASE_URL"] = os.getenv(
    "TEST_DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/postgres"
)
os.environ.setdefault("CGC_APP_ROLE_PASSWORD", "test-only-cgc-app-password-" + uuid.uuid4().hex[:12])


@pytest.fixture(scope="session")
def db():
    """
    The real Database() singleton, pointed at the test Postgres.
    Skips every test that depends on this fixture if no test DB is
    reachable, instead of erroring the whole collection.
    """
    from app.Core.db.database import get_database

    database = get_database()
    if not database.use_postgres:
        pytest.skip("No test Postgres reachable (set TEST_DATABASE_URL) -- skipping DB-backed tests")
    return database


@pytest.fixture(scope="session")
def rls_ready(db):
    """
    Ensures uuid-ossp lives in an `extensions` schema (matching Supabase's
    real convention, which the pod_ledger policy's SQL depends on being
    schema-qualified against) and that the cgc_app role + all 8 RLS
    policies exist, before any isolation test runs.
    """
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("CREATE SCHEMA IF NOT EXISTS extensions")
        cur.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp" SCHEMA extensions')
        conn.commit()
    db._create_rls_policies()
    return True


@pytest.fixture
def cgc_app_dsn():
    """
    Connection string for the real cgc_app role, for tests that need to
    connect AS the RLS-restricted role rather than the admin one.

    Against a plain Postgres (CI's service container), the role name is
    just `cgc_app`. Against Supabase's Supavisor pooler (e.g. running
    this suite locally with TEST_DATABASE_URL pointed at a real Supabase
    project instead), the pooler requires a tenant-qualified username --
    `cgc_app.<project-ref>` -- inferred here from whatever suffix the
    admin DSN's own username already has, so this works unmodified
    against either target.
    """
    base = os.environ["DATABASE_URL"]
    password = os.environ["CGC_APP_ROLE_PASSWORD"]
    prefix, rest = base.split("://", 1)
    creds, hostpart = rest.split("@", 1)
    admin_user = creds.split(":", 1)[0]
    suffix = "." + admin_user.split(".", 1)[1] if "." in admin_user else ""
    return f"{prefix}://cgc_app{suffix}:{password}@{hostpart}"
