import os
import tempfile
import pandas as pd
from flask import Flask, request, jsonify, session, render_template, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from database import Database
import logging
import json
import time
from database import db  # Ensure database initializes on startup
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_bcrypt import Bcrypt
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from database import Database

# Instantiate database and create tables
db = Database()


# Initialize Flask app
app = Flask(__name__, static_folder="static")
app.secret_key = 'my_very_secret_key_1234567890'  # Change this for production
users = [{"id": 1, "username": "admin"}]
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Instantiate the database module
db = Database()

# Global variables to store uploaded data
global_df = None
global_columns = []

# ------------------------------ #
#    Database Initialization     #
# ------------------------------ #

def initialize_database():
    """Create tables if they don’t exist and ensure admin account is created."""
     # Ensure table creation (implemented in `database.py`)

    admin = db.get_admin("admin")  # Check if admin exists
    if not admin:
        hashed_password = generate_password_hash("admin123")  # Store hashed password
        db.add_admin("admin", hashed_password, "admin@example.com", "Administrator")
        print("✅ Admin account created: admin / admin123")

initialize_database()  # Run database initialization

# ------------------------------ #
#           USER ROUTES          #
# ------------------------------ #

@app.route("/")
def index():
    """User Login Page (Default)"""
    return render_template("login.html")

@app.route('/login', methods=['POST'])
def login():
    """User Login"""
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required"}), 400

    # Check credentials against the database
    user = db.get_user(username)

    if user and check_password_hash(user["password"], password):  # Ensure hashed password matches
        session['logged_in'] = True
        session['username'] = username
        session.permanent = True  # Keep session persistent
        return jsonify({"status": "success", "message": "Login successful!"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401

# MongoDB Configuration
app.config["MONGO_URI"] = "mongodb://localhost:27017/your_database"
mongo = PyMongo(app)
bcrypt = Bcrypt(app)


@app.route('/dashboard')
def dashboard():
    """User Dashboard - Only Accessible if Logged In"""
    if not session.get('logged_in'):
        return redirect(url_for('index'))
    return render_template("dashboard.html")

@app.route('/logout')
def logout():
    """Logout for Both Users and Admins"""
    session.clear()
    return redirect(url_for('index'))

# ------------------------------ #
#         ADMIN ROUTES           #
# ------------------------------ #

@app.route('/admin')
def admin_login_page():
    """Admin Login Page"""
    return render_template("admin_login.html")


@app.route("/admin/login", methods=["POST"])
def admin_login():
    username = request.form.get("username")
    password = request.form.get("password")
    
    admin = mongo.db.admins.find_one({"username": username})
    if admin and bcrypt.check_password_hash(admin["password"], password):
        session["admin_username"] = username
        return redirect(url_for("admin_dashboard"))
    
    return "Invalid credentials", 401

    """Admin Login with Proper Authentication"""
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"status": "error", "message": "Username and password are required"}), 400

    admin = db.get_admin(username)
    
    print(f"📌 Debugging: Received login for {username}, DB Password: {admin['password'] if admin else 'Not Found'}")

    if not admin:
        return jsonify({"status": "error", "message": "Admin not found"}), 401

    # Direct password comparison (TEMPORARY)
    if admin["password"] == password:
        session['admin_logged_in'] = True
        session['admin_username'] = username
        session.permanent = True  # Keep session persistent
        return jsonify({"status": "success", "message": "Admin login successful!"})
    else:
        return jsonify({"status": "error", "message": "Invalid credentials"}), 401
    
@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin Dashboard - Only Accessible if Admin Logged In"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login_page'))

    users = db.get_all_users()  # Fetch users from the database
    return render_template("admin.html", 
                           admin_username=session.get('admin_username'), 
                           users=users, 
                           time=time)

@app.route('/admin/logout')
def admin_logout():
    """Admin Logout"""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login_page'))

# ------------------------------ #
#      ADMIN USER MANAGEMENT     #
# ------------------------------ #

@app.route("/admin/add_user", methods=["POST"])
def add_user():
    if "admin_username" not in session:
        return jsonify({"message": "Unauthorized"}), 403

    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    mongo.db.users.insert_one({"username": username, "password": hashed_password})

    return jsonify({"message": "User added successfully"}), 201

@app.route("/admin/edit_user/<user_id>", methods=["PUT"])
def edit_user(user_id):
    if "admin_username" not in session:
        return jsonify({"message": "Unauthorized"}), 403

    new_username = request.json.get("username")
    if not new_username:
        return jsonify({"message": "Username is required"}), 400

    mongo.db.users.update_one({"_id": ObjectId(user_id)}, {"$set": {"username": new_username}})
    return jsonify({"message": "User updated successfully"}), 200

@app.route("/admin/delete_user/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    if "admin_username" not in session:
        return jsonify({"message": "Unauthorized"}), 403

    mongo.db.users.delete_one({"_id": ObjectId(user_id)})
    return jsonify({"message": "User deleted successfully"}), 200

# ------------------------------ #
#       FILE UPLOAD ROUTE        #
# ------------------------------ #

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle File Upload and Store Data"""
    global global_df, global_columns
    file = request.files.get('file')

    if not file:
        return jsonify({"status": "error", "message": "No file uploaded"}), 400

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=file.filename) as temp_file:
            temp_file.write(file.read())
            temp_path = temp_file.name

        success, message, numeric_maxes = db.insert_data(temp_path)
        if success:
            df = pd.read_csv(temp_path) if file.filename.endswith('.csv') else pd.read_excel(temp_path)
            global_df = df
            global_columns = df.columns.tolist()

            response = {
                "status": "success",
                "message": message,
                "columns": global_columns,
                "numericMax": numeric_maxes
            }
        else:
            response = {"status": "error", "message": message}

        os.unlink(temp_path)
        return jsonify(response)

    except Exception as e:
        logger.error("Error in file upload: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500

# ------------------------------ #
#        SEARCH FUNCTION         #
# ------------------------------ #

@app.route('/search', methods=['POST'])
def search():
    """Search Uploaded Data with Filters"""
    global global_df
    if global_df is None:
        return jsonify({"status": "error", "message": "No data available"}), 400

    data = request.get_json()
    filters = data.get('filters', {})
    selected_columns = data.get('selectedColumns', [])
    filtered_df = global_df.copy()

    try:
        for column, filter_values in filters.items():
            if "range" in filter_values:
                min_range, max_range = filter_values["range"]
                filtered_df = filtered_df[(filtered_df[column] >= min_range) & (filtered_df[column] <= max_range)]
            elif "text" in filter_values:
                filtered_df = filtered_df[
                    filtered_df[column].astype(str).str.contains(filter_values["text"], case=False, na=False)
                ]

        if selected_columns:
            filtered_df = filtered_df[selected_columns]

        filtered_df = filtered_df.where(pd.notnull(filtered_df), "None")
        results = filtered_df.to_dict(orient='records')

        response = {
            "status": "success",
            "results": json.loads(json.dumps(results, default=str)),
            "record_count": len(results)
        }
        return jsonify(response)

    except Exception as e:
        logger.error("Unexpected error: %s", e)
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
