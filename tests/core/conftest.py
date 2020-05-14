import pytest
from sqlalchemy import create_engine

from eth_orm.models import Base
from eth_orm.session import Session


@pytest.fixture(scope="session")
def engine():
    # PRO-TIP: Set `echo=True` for lots more SQL debug log output.
    return create_engine("sqlite:///:memory:", echo=False)


@pytest.fixture(scope="session")
def _schema(engine):
    Base.metadata.create_all(engine)


@pytest.fixture(scope="session")
def _Session(engine, _schema):
    Session.configure(bind=engine)
    return Session


@pytest.fixture
def session(_Session, _schema):
    session = Session()
    transaction = session.begin_nested()
    session.commit = lambda: None

    try:
        yield session
    finally:
        transaction.rollback()
        session.close()
