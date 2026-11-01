"""Check PostgreSQL CI isolation without ever opening a PostgreSQL connection."""

import pytest

from integration.test_postgres_migrations import ci_database_url

VALID_ENVIRONMENT = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_RUN_ID": "41252988413",
    "GITHUB_RUN_ATTEMPT": "1",
    "CCVM_POSTGRES_TEST_PORT": "32768",
}


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_ACTIONS", ""),
        ("GITHUB_ACTIONS", "false"),
        ("GITHUB_RUN_ID", ""),
        ("GITHUB_RUN_ID", "../production"),
        ("GITHUB_RUN_ID", "0"),
        ("GITHUB_RUN_ID", "1" * 21),
        ("GITHUB_RUN_ATTEMPT", ""),
        ("GITHUB_RUN_ATTEMPT", "0"),
        ("GITHUB_RUN_ATTEMPT", "1;DROP DATABASE ccvm"),
        ("GITHUB_RUN_ATTEMPT", "1" * 11),
        ("CCVM_POSTGRES_TEST_PORT", ""),
        ("CCVM_POSTGRES_TEST_PORT", "5432/production"),
        ("CCVM_POSTGRES_TEST_PORT", "1023"),
        ("CCVM_POSTGRES_TEST_PORT", "65536"),
    ],
)
def test_invalid_ci_environment_is_rejected(key, value):
    with pytest.raises(ValueError):
        ci_database_url({**VALID_ENVIRONMENT, key: value})


def test_missing_environment_is_rejected():
    with pytest.raises(ValueError):
        ci_database_url({})


def test_inherited_database_configuration_cannot_select_a_target():
    url = ci_database_url(
        {
            **VALID_ENVIRONMENT,
            "DATABASE_URL": "postgresql://real-user:real-password@production.invalid/ccvm",
            "DB_HOST": "production.invalid",
            "DB_NAME": "ccvm",
            "PGHOSTADDR": "192.0.2.1",
            "PGSERVICE": "production",
            "CCVM_POSTGRES_TEST_URL": "postgresql://production.invalid/ccvm",
        }
    )
    assert url.drivername == "postgresql+psycopg2"
    assert url.host == "127.0.0.1"
    assert url.port == 32768
    assert url.database == "ccvm_ci_41252988413_1"
    assert url.username == "ccvm_ci"
    assert url.password == "ccvm_ci_only"
    assert url.query == {"connect_timeout": "5", "hostaddr": "127.0.0.1"}


def test_retry_uses_a_different_temporary_database():
    original = ci_database_url(VALID_ENVIRONMENT)
    retried = ci_database_url({**VALID_ENVIRONMENT, "GITHUB_RUN_ATTEMPT": "2"})
    assert original.database != retried.database
