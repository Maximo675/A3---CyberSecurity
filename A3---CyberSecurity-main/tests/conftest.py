import os
import sys
import tempfile
import pytest

# Ensure project root is on sys.path for module resolution
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app, db, User, set_password


@pytest.fixture
def test_app(tmp_path, monkeypatch):
    # Setup env for testing
    monkeypatch.setenv('SECRET_KEY', 'test-secret')
    monkeypatch.setenv('ADMIN_PASS', 'ChangeMe123!')

    # Create a temporary sqlite database for tests
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.app_context():
        db.create_all()
        # Create an admin and a volunteer for testing if they do not exist
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password_hash=set_password('adminpass'), role='admin')
            db.session.add(admin)
        if not User.query.filter_by(username='vol').first():
            vol = User(username='vol', password_hash=set_password('volpass'), role='voluntario')
            db.session.add(vol)
        db.session.commit()

    yield app

    # Cleanup
    with app.app_context():
        db.session.remove()
        db.drop_all()
    os.close(db_fd)
    os.remove(db_path)


@pytest.fixture
def client(test_app):
    return test_app.test_client()
