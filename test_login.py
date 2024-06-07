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
