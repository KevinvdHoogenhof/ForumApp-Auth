import pytest
import os

os.environ['FLASK_ENV'] = 'testing'

from app import app, db, User
from flask_jwt_extended import create_access_token
import json

@pytest.fixture(scope='module')
def test_client():
    app.config['TESTING'] = True

    with app.test_client() as testing_client:
        with app.app_context():
            db.create_all()
            yield testing_client
            db.drop_all()

@pytest.fixture(autouse=True)
def clear_db():
    db.session.query(User).delete()
    db.session.commit()

@pytest.mark.parametrize("email, password, status_code, description", [
    ("test@example.com", "password123", 200, "Valid login"),
    ("invalid@example.com", "password123", 401, "Invalid email"),
    ("test@example.com", "wrongpassword", 401, "Invalid password"),
    ("", "password123", 401, "Missing email"),
    ("test@example.com", "", 401, "Missing password")
])
def test_login(email, password, status_code, description, test_client):
    # Create a test user if the test case is for valid login
    if description == "Valid login":
        user = User(username='test_user', email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
    
    # Attempt to log in
    response = test_client.post('/login', json={
        'email': email,
        'password': password
    })
    
    assert response.status_code == status_code, f"{description}: Expected {status_code}, got {response.status_code}"
    if response.status_code == 200:
        # Verify the token is in the response
        data = response.get_json()
        assert 'access_token' in data, "Access token is missing in the response"

def test_protected_endpoint_unauthorized(test_client):
    response = test_client.get('/protected')
    assert response.status_code == 401

def test_protected_endpoint_authorized(test_client):
    # Create a test user
    user = User(username='test_user', email='test@example.com')
    user.set_password('password123')
    db.session.add(user)
    db.session.commit()

    # Obtain JWT token for the test user
    access_token = create_access_token(identity={'id': user.id, 'username': user.username})

    # Make request to the protected endpoint with JWT token
    headers = {'Authorization': f'Bearer {access_token}'}
    response = test_client.get('/protected', headers=headers)
    assert response.status_code == 200

    # Check if the response contains the expected user information
    data = json.loads(response.data)
    assert data['logged_in_as']['username'] == 'test_user'
