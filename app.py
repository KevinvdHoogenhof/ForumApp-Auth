from flask import Flask, jsonify, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate, upgrade
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'postgresql://postgres:mysecretpassword@localhost/authdb'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app,db)

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
def apply_migrations():
    from flask_migrate import upgrade
    from sqlalchemy import inspect
    from sqlalchemy.exc import ProgrammingError

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
    return render_template('index.html')

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
        else:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'Email already exists'}), 400

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        return jsonify({'message': 'User registered successfully'})
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        if request.content_type == 'application/json':
            data = request.get_json()
            #username = data.get('username')
            email = data.get('email')
            password = data.get('password')
        else:
            #username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            #access_token = create_access_token(identity={'id': user.id, 'name': user.name})
            #return jsonify(access_token=access_token), 200
            return jsonify({'message': 'Login successful', 'username': user.username})

        return jsonify({'message': 'Invalid email or password'}), 401
    return render_template('login.html')

@app.route('/hello/<username>')
def hello(username):
    return f"Hello, {username}!"

if __name__ == '__main__':
    #db.create_all()
    app.run(host='0.0.0.0', debug=True)
