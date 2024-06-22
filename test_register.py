import pytest
import os

os.environ['FLASK_ENV'] = 'testing'

from app import app, db, User

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

test_data = [
    {"username": "user1", "email": "user1@example.com", "password": "short", "status_code": 400, "description": "Password too short"},
    {"username": "user2", "email": "user2@example.com", "password": "noSpecialChar123", "status_code": 400, "description": "Password missing special character"},
    {"username": "user3", "email": "user3@example.com", "password": "NoDigits!!", "status_code": 400, "description": "Password missing digits"},
    {"username": "user4", "email": "user4@example.com", "password": "validPass123!", "status_code": 200, "description": "Valid password"},
    {"username": "user5", "email": "user5@example.com", "password": "ThisIsAReallyReallyLongPassword123!", "status_code": 200, "description": "Very long but valid password"},
    {"username": "user6", "email": "user6@example.com", "password": "invalid@char^&", "status_code": 400, "description": "Password with invalid special characters"},
    {"username": "user7", "email": "user7@example.com", "password": "lowercase", "status_code": 400, "description": "Password with no uppercase"},
    {"username": "user8", "email": "user8@example.com", "password": "UPPERCASE", "status_code": 400, "description": "Password with no lowercase"}
]

@pytest.mark.parametrize("data", test_data)
def test_register(data, test_client):
    response = test_client.post('/register', json={"username": data["username"], "email": data["email"], "password": data["password"]})
    assert response.status_code == data["status_code"], f"{data['description']}: Expected {data['status_code']}, got {response.status_code}"
    if response.status_code != data["status_code"]:
        print(f"Response message: {response.get_json()}") # pragma: no cover

def test_duplicate_email(test_client):
    # Register the first time
    response = test_client.post('/register', json={"username": "uniqueUser", "email": "duplicateEmail@example.com", "password": "ValidPass1!"})
    assert response.status_code == 200, "Initial registration failed"
    if response.status_code != 200:
        print(f"Response message: {response.get_json()}") # pragma: no cover

    # Register with the same email again
    response = test_client.post('/register', json={"username": "uniqueUser2", "email": "duplicateEmail@example.com", "password": "ValidPass2!"})
    assert response.status_code == 400, "Duplicate email check failed"
    if response.status_code != 400:
        print(f"Response message: {response.get_json()}") # pragma: no cover

def test_missing_email(test_client):
    response = test_client.post('/register', json={"username": "user1", "password": "ValidPass1!"})
    assert response.status_code == 400, "Missing email registration succeeded"

def test_valid_email(test_client):
    response = test_client.post('/register', json={"username": "user1", "email": "valid_email@example.com", "password": "ValidPass1!"})
    assert response.status_code == 200, "Valid email registration failed"

def test_invalid_email(test_client):
    response = test_client.post('/register', json={"username": "user2", "email": "invalid_email", "password": "ValidPass1!"})
    assert response.status_code == 400, "Invalid email registration succeeded"
    response_data = response.get_json()
    assert "error" in response_data and "Invalid email address format." in response_data["error"], "Invalid email error message incorrect"
