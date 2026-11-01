import hashlib
import os
import socket
import subprocess

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

# Override even an inherited production URL before any app modules are imported.
os.environ["DATABASE_URL"] = "sqlite://"


@pytest.fixture(autouse=True)
def prevent_external_io(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Tests must not open network connections or launch scanner processes")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)


@pytest.fixture
def client():
    from app.database.deps import get_db
    from app.database.session import Base
    from app.main import app

    # A fresh, private in-memory database for each test; no files or services.
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, connection_record):
        connection.execute("PRAGMA foreign_keys=ON")
        connection.create_function(
            "sha256", 1, lambda value: hashlib.sha256(value).digest(), deterministic=True
        )

    try:
        Base.metadata.create_all(engine)
        with Session(engine) as session:

            def override_get_db():
                yield session

            app.dependency_overrides[get_db] = override_get_db
            try:
                with TestClient(app) as test_client:
                    yield test_client
            finally:
                app.dependency_overrides.pop(get_db, None)
    finally:
        engine.dispose()


@pytest.fixture
def customer(client):
    response = client.post(
        "/api/v1/customers",
        json={"name": "CI Customer", "company": "CI Company"},
    )
    assert response.status_code == 200
    return response.json()


@pytest.fixture
def domain(client, customer):
    response = client.post(
        "/api/v1/domains",
        json={"customer_id": customer["id"], "name": "example.test"},
    )
    assert response.status_code == 200
    return response.json()
