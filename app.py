from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Dummy database for demonstration
users = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users[username] = password
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if users.get(username) == password:
            return redirect(url_for('hello', username=username))
        else:
            return "Invalid credentials. Please try again."
    return render_template('login.html')

@app.route('/hello/<username>')
def hello(username):
    return f"Hello, {username}!"

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
