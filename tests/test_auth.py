import pytest
from app import create_app, db
from app.models import User

@pytest.fixture
def client():
    app = create_app()
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

def test_signup(client):
    response = client.post('/auth/signup', data={
        'name': 'Test User',
        'email': 'test@example.com',
        'password': 'Password1',
        'confirm_password': 'Password1'
    }, follow_redirects=True)
    assert b'Check your inbox for a confirmation email' in response.data

def test_login_logout(client):
    # Create user directly
    user = User(name='Test', email='login@example.com')
    user.set_password('Password1')
    db.session.add(user)
    db.session.commit()
    # Login
    response = client.post('/auth/login', data={
        'email': 'login@example.com',
        'password': 'Password1'
    }, follow_redirects=True)
    assert b'Dashboard' in response.data
    # Logout
    response = client.get('/auth/logout', follow_redirects=True)
    assert b'Login' in response.data

def test_password_reset(client):
    # Add user
    user = User(name='Reset', email='reset@example.com')
    user.set_password('Password1')
    db.session.add(user)
    db.session.commit()
    # Request reset
    response = client.post('/auth/request_reset', data={
        'email': 'reset@example.com'
    }, follow_redirects=True)
    assert b'Check your email for a password reset link' in response.data