"""Shared pytest fixtures for the per-protocol database test suites.

Each protocol database is exercised in its own isolated workspace ("test_<proto>"),
so the per-protocol test modules can run independently (and concurrently) without
clobbering each other's sqlite files. A single session-scoped registry builds and
caches each protocol's database object on first use and tears everything down at the
end of the session.
"""
import os

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker

from nxc.database import create_workspace, delete_workspace
from nxc.first_run import first_run_setup
from nxc.loaders.protocolloader import ProtocolLoader
from nxc.logger import NXCAdapter
from nxc.paths import WORKSPACE_DIR


def _build_protocol_db(proto):
    """Create an isolated 'test_<proto>' workspace and return (db_obj, engine, workspace_name)."""
    workspace_name = f"test_{proto}"
    first_run_setup(NXCAdapter())
    p_loader = ProtocolLoader()
    create_workspace(workspace_name, p_loader)

    db_path = os.path.join(WORKSPACE_DIR, f"{workspace_name}/{proto}.db")
    engine = create_engine(f"sqlite:///{db_path}", isolation_level="AUTOCOMMIT", future=True)

    proto_db_path = p_loader.get_protocols()[proto]["dbpath"]
    proto_db_object = p_loader.load_protocol(proto_db_path).database

    db_obj = proto_db_object(engine)
    db_obj.reflect_tables()
    return db_obj, engine, workspace_name


class _ProtocolDBRegistry:
    """Builds protocol database objects on demand and caches them per protocol."""

    def __init__(self):
        self._built = {}      # proto -> (db_obj, engine, workspace_name)
        self._sessions = []

    def db(self, proto):
        if proto not in self._built:
            self._built[proto] = _build_protocol_db(proto)
        return self._built[proto][0]

    def session(self, proto):
        """A raw SQLAlchemy session bound to the protocol's engine (for direct inserts)."""
        self.db(proto)  # ensure the engine/workspace exists
        _, engine, _ = self._built[proto]
        sess = scoped_session(sessionmaker(bind=engine, expire_on_commit=True))()
        self._sessions.append(sess)
        return sess

    def teardown(self):
        for sess in self._sessions:
            sess.close()
        for db_obj, engine, workspace_name in self._built.values():
            db_obj.shutdown_db()
            engine.dispose()
            delete_workspace(workspace_name)


@pytest.fixture(scope="session")
def protocol_dbs():
    """Session-scoped registry. Use `protocol_dbs.db("<proto>")` / `.session("<proto>")`."""
    registry = _ProtocolDBRegistry()
    yield registry
    registry.teardown()
