from alembic.config import Config
from alembic.script import ScriptDirectory


def test_migration_history_has_one_reachable_head():
    # Inspects revision files only; never opens a database or applies migrations.
    script = ScriptDirectory.from_config(Config("alembic.ini"))
    head = script.get_current_head()
    assert head is not None
    revisions = list(script.walk_revisions())
    assert revisions[0].revision == head
    assert revisions[-1].down_revision is None
