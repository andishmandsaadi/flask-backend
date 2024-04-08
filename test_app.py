import pytest
from app import create_app, db, User

@pytest.fixture(scope='module')
def test_app():
    # Create application context
    app = create_app()
    with app.app_context():
        with app.app_context():
            db.drop_all()  # Drop all tables
            db.create_all()  # Recreate them
            yield app
            db.session.remove()
            db.drop_all()

@pytest.fixture
def auth_header(client):
    response = client.post('/auth/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    access_token = response.json.get('access_token')
    return {'Authorization': f'Bearer {access_token}'}

@pytest.fixture(scope='module')
def client(test_app):
    return test_app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

def test_create_user(client, test_app):
    with test_app.app_context():
        response = client.post('/user/', json={
            'username': 'testuser',
            'email': 'test@example.com',
            'password': 'testpassword'
        })
        print(response.text)
        assert response.status_code == 201
        assert b"User created successfully." in response.data

        # Verify user is in database
        user = User.query.first()
        assert user.username == 'testuser'

def test_valid_login(client):
    # Assuming a user already exists
    response = client.post('/auth/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    assert b"access_token" in response.data

def test_invalid_login(client):
    response = client.post('/auth/login', json={
        'username': 'user_does_not_exist',
        'password': 'wrong_password'
    })
    assert response.status_code == 401
    assert b"Bad username or password" in response.data

def test_protected_endpoint(client, auth_header):
    response = client.get('/auth/protected', headers=auth_header)
    assert response.status_code == 200
    assert b"logged_in_as" in response.data


def test_analyze_text(client, auth_header):
    response = client.post('/text/analyze', json={
        'text': 'I love Python!'
    }, headers=auth_header)

    assert response.status_code == 200
    data = response.get_json()
    assert 'sentiment' in data
    assert 'compound' in data['sentiment']

def test_extract_entities(client, auth_header):
    response = client.post('/text/extract-entities', json={
        'text': 'Google was founded in September 1998 by Larry Page and Sergey Brin while they were Ph.D. students at Stanford University.'
    }, headers=auth_header)

    assert response.status_code == 200
    data = response.get_json()
    assert 'entities' in data

def test_detect_language(client, auth_header):
    response = client.post('/text/detect-language', json={
        'text': 'This is an English text.'
    }, headers=auth_header)

    assert response.status_code == 200
    data = response.get_json()
    assert 'language' in data
    assert data['language'] == 'en'


def test_update_user(client,auth_header):
    # Create a user to update
    new_email = 'test@example.com'
    response = client.put('/user/update/testuser', json={'email': new_email}, headers=auth_header)
    assert response.status_code == 200
    assert b"User updated successfully." in response.data

    # Verify the user's email was updated
    user = User.query.filter_by(username='testuser').first()
    assert user.email == new_email

def test_get_user(client, auth_header):
    # Assuming 'testuser' already exists
    response = client.get('/user/testuser', headers=auth_header)

    assert response.status_code == 200
    assert b"testuser" in response.data

def test_delete_user(client, auth_header):
    # Delete the user
    response = client.delete('/user/delete/testuser', headers=auth_header)

    assert response.status_code == 200
    assert b"User deleted successfully." in response.data

    # Verify the user was removed from the database
    user = User.query.filter_by(username='testuser').first()
    assert user is None

