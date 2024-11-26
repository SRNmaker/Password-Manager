from flask import Flask, render_template, request, flash, redirect, url_for
from flask_cors import CORS
from dataBase import Database
from threading import Lock
import sign_up

app = Flask(__name__)
CORS(app)
app.secret_key = "example"

#def initialize_database():
# Initialize database with thread-safe configuration
db_path = r"C:\PythonPrograming\Password Manager\secure_users.db"
db_lock = Lock()  # To ensure thread-safe access to the database

db = Database(db_path=db_path)
db.connect()
db.create_tables()

# Helper function to safely execute queries in routes
def with_db_connection(func):
    """Decorator to manage database connection and locking."""
    def wrapper(*args, **kwargs):
        with db_lock:
            db.connect()
            result = func(*args, **kwargs)
            return result
    wrapper.__name__ = func.__name__ + "_decorated"  # Ensure unique function names
    return wrapper

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@with_db_connection
def login():
    if request.method == 'POST':
        # Handle login logic here
        username = request.form['username']
        password = request.form['password']
        # Authenticate user
        success = db.log_in(raw_userID=username, raw_masterPass=password)
        if success: 
            return redirect(url_for("home_decorated")) 
        else: 
            flash('Invalid username or password. Please try again.')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
@with_db_connection
def signup():
    if request.method == 'POST':
        # Handle sign up logic here
        password = request.form['password']
        # Register user
        userId = sign_up.signUp()
    return render_template('signup.html')

@app.route(f"/userdata/homepage")
@with_db_connection
def home():
    return render_template("home.html")

if __name__ == '__main__':
    port = 5000  # Default port for Flask
    url = f"http://127.0.0.1:{port}/"
    print(f"Starting server at {url}")
    app.run(debug=True, port=port)
    