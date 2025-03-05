from app import create_app, db
from app.models import User
import pytest

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()

def test_register(client):
    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'testpass'
    })
    assert response.status_code == 302  # Redirect

def test_login(client):
    client.post('/register', data={'username': 'test', 'password': 'test'})
    response = client.post('/login', data={
        'username': 'test',
        'password': 'test'
    })
    assert b'verify_2fa' in response.data