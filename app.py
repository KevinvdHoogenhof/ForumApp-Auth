from flask import Flask, jsonify, render_template, request, redirect, url_for
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, decode_token, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate, upgrade
from datetime import timedelta
import re
import os
from confluent_kafka import Producer

app = Flask(__name__)

# Check for the testing environment
if os.environ.get('FLASK_ENV') == 'testing':
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'postgresql://postgres:mysecretpassword@localhost/authdb' # pragma: no cover
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
jwt = JWTManager(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app,db)
KAFKA_SERVER_URL = os.environ.get('KAFKA_SERVER_URL', 'localhost:9092')
producer = Producer({'bootstrap.servers': KAFKA_SERVER_URL})

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

# Check if database is initialized and apply migrations if needed
def apply_migrations(): # pragma: no cover
    from flask_migrate import upgrade
    from sqlalchemy import inspect
    from sqlalchemy.exc import ProgrammingError

    if os.environ.get('FLASK_ENV') == 'testing':
        return  # Skip migrations in testing environment
    
    try:
        with app.app_context():
            inspector = inspect(db.engine)
            if not inspector.has_table('user'):
                db.create_all()
                upgrade()
    except ProgrammingError as e:
        if 'relation "user" already exists' in str(e):
            pass  # Skip table creation, as it already exists
        else:
            raise e

# Apply migrations when the application starts
apply_migrations()

@app.route('/')
def index():
    return render_template('index.html') # pragma: no cover

# Function to check if email is valid
def is_valid_email(email):
    """
    Validates the email address format.
    """
    # Regular expression pattern for validating email address
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Password policy function
def is_valid_password(password):
    """
    Validates the password based on defined policies:
    - At least 8 characters long
    - Contains at least one uppercase letter
    - Contains at least one lowercase letter
    - Contains at least one digit
    - Contains at least one special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, "Password must contain at least one special character."
    return True, "Password is valid."

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST': 
        #data = request.get_json()
        #username = data.get('username')
        #email = data.get('email')
        #password = data.get('password')
        if request.content_type == 'application/json':
            data = request.get_json()
            username = data.get('username')
            email = data.get('email')
            password = data.get('password')
        else: # pragma: no cover
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')

        if not username or not password or not email:
            return jsonify({"error": "Username, password and email are required."}), 400

        is_valid_pw, message = is_valid_password(password)
        if not is_valid_pw:
            return jsonify({"error": message}), 400

        is_valid_email_address = is_valid_email(email)
        if not is_valid_email_address:
            return jsonify({"error": "Invalid email address format."}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'Email already exists'}), 400

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'})
    return render_template('register.html') # pragma: no cover

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.content_type == 'application/json':
            data = request.get_json()
            #username = data.get('username')
            email = data.get('email')
            password = data.get('password')
        else: # pragma: no cover
            #username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            access_token = create_access_token(identity={'id': user.id, 'username': user.username})
            return jsonify(access_token=access_token), 200
            #return jsonify({'message': 'Login successful', 'username': user.username})

        return jsonify({'message': 'Invalid email or password'}), 401
    return render_template('login.html') # pragma: no cover

@app.route('/users', methods=['GET'])
def users(): # pragma: no cover
    users = User.query.all()
    user_list = []

    for user in users:
        user_data = {
            'id': user.id,
            'username': user.username,
            #'email': user.email,
            #'password_hash': user.password_hash
        }
        user_list.append(user_data)

    return jsonify({'users': user_list}), 200

@app.route('/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id): # pragma: no cover
    user = User.query.get(user_id)

    if not user:
        return jsonify({'message': 'User not found'}), 404

    db.session.delete(user)
    db.session.commit()

    # Produce a message to Kafka topic
    topic = 'accountdeleted'
    message = f'{user_id} has deleted their account'
    producer.produce(topic, message.encode('utf-8'))
    producer.flush()

    return jsonify({'message': 'User deleted successfully'}), 200

# Endpoint for token validation
@app.route('/validate-token', methods=['POST'])
def validate_token(): # pragma: no cover
    token = request.json.get('access_token', None)

    if not token:
        return jsonify({'message': 'Access token is missing'}), 400

    try:
        decoded_token = decode_token(token)
        return jsonify({'valid': True, 'identity': decoded_token['sub']}), 200
    except Exception as e:
        return jsonify({'valid': False, 'error': str(e)}), 401

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/hello/<username>')
def hello(username): # pragma: no cover
    return f"Hello, {username}!"

if __name__ == '__main__': # pragma: no cover
    #db.create_all()
    app.run(host='0.0.0.0', debug=True)
