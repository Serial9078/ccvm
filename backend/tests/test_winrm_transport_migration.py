import pytest
import sqlalchemy as sa

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.operations import Operations
from alembic.script import ScriptDirectory


@pytest.fixture
def old_history():
    engine = sa.create_engine("sqlite://")
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "CREATE TABLE host_audits (id INTEGER PRIMARY KEY, scope_sha256 TEXT NOT NULL, "
            "inventory TEXT)"
        )
        connection.execute(
            sa.text("INSERT INTO host_audits VALUES (1, :hash, :inventory)"),
            {"hash": "f" * 64, "inventory": '{"os":{"family":"Windows"}}'},
        )
        module = (
            ScriptDirectory.from_config(Config("alembic.ini")).get_revision("b7e2c9d1a630").module
        )
        with Operations.context(MigrationContext.configure(connection)):
            yield connection, module
    engine.dispose()


def test_transport_migration_backfills_without_rewriting_hash_or_evidence(old_history):
    connection, migration = old_history
    before = connection.exec_driver_sql("SELECT * FROM host_audits").mappings().one()
    migration.upgrade()
    after = connection.exec_driver_sql("SELECT * FROM host_audits").mappings().one()
    assert dict(after) == {**before, "winrm_transport": "https"}
    with pytest.raises(sa.exc.IntegrityError):
        connection.exec_driver_sql(
            "INSERT INTO host_audits (id, scope_sha256, winrm_transport) VALUES (2, 'x', NULL)"
        )


def test_transport_downgrade_can_represent_unchanged_https_history(old_history):
    connection, migration = old_history
    before = list(connection.exec_driver_sql("SELECT * FROM host_audits").mappings())
    migration.upgrade()
    migration.downgrade()
    assert list(connection.exec_driver_sql("SELECT * FROM host_audits").mappings()) == before


def test_transport_downgrade_refuses_to_erase_http_history(old_history):
    connection, migration = old_history
    migration.upgrade()
    connection.exec_driver_sql("UPDATE host_audits SET winrm_transport='http_ntlm'")
    before = list(connection.exec_driver_sql("SELECT * FROM host_audits").mappings())
    with pytest.raises(RuntimeError, match="HTTP WinRM history exists"):
        migration.downgrade()
    assert list(connection.exec_driver_sql("SELECT * FROM host_audits").mappings()) == before
