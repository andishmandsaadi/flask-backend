import pytest
from app import app, db,User

@pytest.fixture(scope='module')
def test_app():
    # Create application context
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()

@pytest.fixture
def auth_header(client):
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    access_token = response.json['access_token']
    return {'Authorization': f'Bearer {access_token}'}


@pytest.fixture(scope='module')
def client(test_app):
    return test_app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

def test_home(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b"Welcome to the Text Analysis Flask Backend!" in response.data

def test_create_user(client):
    response = client.post('/users', json={
        'username': 'testuser',
        'email': 'test@example.com',
        'password': 'testpassword'
    })
    assert response.status_code == 201
    assert b"User created successfully." in response.data

    # Verify user is in database
    with app.app_context():
        user = User.query.first()
        assert user.username == 'testuser'

def test_valid_login(client):
    # Assuming a user already exists
    response = client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    # Check for access token in response
    assert b"access_token" in response.data

def test_invalid_login(client):
    response = client.post('/login', json={
        'username': 'user_does_not_exist',
        'password': 'wrong_password'
    })
    assert response.status_code == 401
    assert b"Bad username or password" in response.data

def test_protected_endpoint_unauthorized(client):
    response = client.get('/protected')
    assert response.status_code == 401
    assert b"msg" in response.data

def test_protected_endpoint_authorized(client, auth_header):
    response = client.get('/protected', headers=auth_header)
    assert response.status_code == 200
    assert b"logged_in_as" in response.data
