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

from flask_bcrypt import Bcrypt



# Initialize Flask app
app = Flask(__name__, static_folder="static")
app.secret_key = 'my_very_secret_key_1234567890'  # Change this for production
users = [{"id": 1, "username": "admin"}]
# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
bcrypt = Bcrypt(app)  # ✅ Initialize bcrypt with Flask app
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"  # ✅ Ensures session is stored properly


from flask_mail import Mail, Message

app.config['MAIL_SERVER'] = 'mail.mmglobus.in'
app.config['MAIL_PORT'] = 465  # ✅ Correct port for SSL
app.config['MAIL_USERNAME'] = 'azzim@mmglobus.in'
app.config['MAIL_PASSWORD'] = 'Azzim@03'  # 🔥 Use the real password or an App Password
app.config['MAIL_USE_TLS'] = False  # ❌ Must be False when using SSL
app.config['MAIL_USE_SSL'] = True  # ✅ Enable SSL for port 465
app.config['MAIL_DEFAULT_SENDER'] = 'azzim@mmglobus.in'  # ✅ Sender email must match username
mail = Mail(app)

def send_welcome_email(user_email, username,password):
    """Send a welcome email to the new user."""
    try:
        msg = Message("Welcome to Spark Search Application", sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[user_email])
        msg.body = f"Hello {username},\n\nYour account has been created successfully.\n\n Your User Name is {username} \n\n Your Password is {password} \n\nBest Regards,\nSpark Admin Team"
        mail.send(msg)
        print(f"✅ Welcome email sent to {user_email}")
    except Exception as e:
        print(f"❌ Error sending welcome email: {e}")

def send_admin_notification(subject, message):
    """Send an email to the admin whenever a user is added or deleted."""
    try:
        admin_email = "azzim@mmglobus.in"  # ✅ Ensure this email exists
        msg = Message(subject, sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[admin_email])
        msg.body = message
        mail.send(msg)
        print(f"✅ Admin notification sent: {subject}")
    except Exception as e:
        print(f"❌ Error sending admin email: {e}")



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
        # db.add_admin("admin", hashed_password, "admin@example.com", "Administrator")
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

    user = db.get_user(username)

    if user:
        stored_hashed_password = user["password"]  # ✅ Retrieve hashed password
        print(f"🔑 Debug: Stored Hash: {stored_hashed_password}")  # Debugging
        print(f"🔑 Debug: Entered Password: {password}")  # Debugging

        # Verify the password using bcrypt
        if bcrypt.check_password_hash(stored_hashed_password, password):
            print("✅ Debug: Password Match!")
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True  # Keep session persistent
            return jsonify({"status": "success", "message": "Login successful!"})

        else:
            print("❌ Debug: Password Incorrect!")

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
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    print(f"📌 Debug: Received login for username: {username}")

    admin = mongo.db.admins.find_one({"username": username})

    if not admin:
        print("❌ Debug: Admin not found in database")
        return jsonify({"status": "error", "message": "Admin not found"}), 401

    stored_password_hash = admin["password"]
    print(f"🔑 Debug: Found admin, stored password hash: {stored_password_hash}")  # Print stored hash
    print(f"🔑 Debug: Password entered: {password}")  # Print entered password

    # Check if the password matches the hash
    if bcrypt.check_password_hash(stored_password_hash, password):
        session["admin_username"] = username
        print("✅ Debug: Login successful!")
        return jsonify({"status": "success", "redirect": "/admin/dashboard"}), 200  # ✅ Send redirect URL

    print("❌ Debug: Password incorrect!")
    return jsonify({"status": "error", "message": "Invalid credentials"}), 401


@app.route('/admin/dashboard')
def admin_dashboard():
    """Admin Dashboard - Only Accessible if Admin Logged In"""
    if "admin_username" not in session:
        print("❌ Debug: Admin not logged in, redirecting to login")
        return redirect(url_for('admin_login_page'))  # ✅ Make sure this is correct

    users = db.get_all_users()  # ✅ Fetch all users
    total_users = len(users)
    
    # Count active users (assuming an 'is_active' column exists)
    active_users = sum(1 for user in users if user.get("is_active", 1) == 1)  # Default to active
    
    # Count admin users (assuming 'role' column exists)
    admin_users = sum(1 for user in users if user.get("role", "user") == "admin")


    print(f"✅ Debug: Users fetched for dashboard: {users}")  # Debugging

    return render_template("admin.html", admin_username=session.get('admin_username'),users=users, 
                           total_users=total_users,
                           active_users=active_users,
                           admin_users=admin_users)


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

    data = request.get_json()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()

    if not username or not email or not password:
        return jsonify({"message": "All fields are required"}), 400

    # Check if email exists
    db.cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    existing_user = db.cursor.fetchone()
    if existing_user:
        return jsonify({"message": "This email is already in use. Please use a different email."}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        db.cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                          (username, hashed_password, email))
        db.conn.commit()
        
        # Get the new user's ID
        new_user_id = db.cursor.lastrowid  

        # Send welcome email to the new user
        send_welcome_email(email, username ,password )

        # Send notification email to admin
        send_admin_notification(
            "New User Added",
            f"Admin,\n\nA new user has been added to the system:\n\nUsername: {username}\nEmail: {email}\n\nBest Regards,\nAdmin Panel"
        )

        return jsonify({"message": "User added successfully", "new_user_id": new_user_id}), 201  # ✅ Return new user ID
    except Exception as e:
        print(f"❌ Error inserting user into SQL: {e}")
        return jsonify({"message": "Failed to add user"}), 500


@app.route("/admin/edit_user/<user_id>", methods=["PUT"])
def edit_user(user_id):
    if "admin_username" not in session:
        return jsonify({"message": "Unauthorized"}), 403

    data = request.get_json()
    new_username = data.get("username", "").strip()

    if not new_username:
        return jsonify({"message": "Username is required"}), 400

    try:
        db.cursor.execute("UPDATE users SET username = ? WHERE id = ?", (new_username, user_id))
        db.conn.commit()
        return jsonify({"message": "User updated successfully"}), 200
    except Exception as e:
        print(f"❌ Error updating user: {e}")
        return jsonify({"message": "Database update failed"}), 500

@app.route("/admin/delete_user/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    if "admin_username" not in session:
        return jsonify({"message": "Unauthorized"}), 403
    

    db.cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.conn.commit()

    send_admin_notification(
            "User Deleted",
            f"Admin,\n\nThe following user has been deleted:\n\nUserID: {user_id}\n\nBest Regards,\nAdmin Panel"
        )


    print(f"✅ Debug: User {user_id} deleted")
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
