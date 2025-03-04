import sqlite3
import pandas as pd
import numpy as np
import logging
from pathlib import Path
from typing import Dict, Union, List, Tuple
from typing import Union
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

# Database file path
DB_PATH = "database.db"


class Database:
    def __init__(self):
        """Initialize database connection and create necessary tables."""
        self.setup_logging()
        Path("data").mkdir(exist_ok=True)  # Ensure data directory exists
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.initialize_database()

    def setup_logging(self):
        """Set up logging configuration."""
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s",
            filename="database.log"
        )
        self.logger = logging.getLogger(__name__)

    def initialize_database(self):
        """Create necessary tables if they don’t exist."""
        try:
            queries = [
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    full_name TEXT NOT NULL,
                    role TEXT CHECK(role IN ('user', 'admin')) DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """,
                """
                CREATE TABLE IF NOT EXISTS resumes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    candidate_name TEXT NOT NULL,
                    experience INTEGER,
                    skills TEXT,
                    education TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            ]

            for query in queries:
                self.cursor.execute(query)

            self.conn.commit()
            self.ensure_admin_exists()

        except Exception as e:
            self.logger.error(f"Error initializing database: {e}")

    def ensure_admin_exists(self):
        """Ensure a default admin exists in the database."""
        try:
            self.cursor.execute("SELECT * FROM users WHERE role = 'admin'")
            if not self.cursor.fetchone():
                self.cursor.execute("""
                INSERT INTO users (username, password, email, full_name, role) 
                VALUES ('admin', 'admin123', 'admin@example.com', 'Administrator', 'admin')
                """)
                self.conn.commit()
        except Exception as e:
            self.logger.error(f"Error ensuring admin exists: {e}")

    def create_table_from_df(self, df: pd.DataFrame) -> None:
        """Dynamically create 'resumes' table based on DataFrame columns."""
        try:
            columns = [f'"{col}" {"REAL" if df[col].dtype in [np.float64, np.int64] else "TEXT"}' for col in df.columns]

            self.cursor.execute("DROP TABLE IF EXISTS resumes")
            self.cursor.execute(f"CREATE TABLE resumes ({', '.join(columns)})")

            # Create indexes for better performance
            for col in df.columns:
                try:
                    self.cursor.execute(f'CREATE INDEX IF NOT EXISTS "idx_{col}" ON resumes("{col}")')
                except sqlite3.OperationalError:
                    self.logger.warning(f"Failed to create index for {col}")

            self.conn.commit()
        except Exception as e:
            self.logger.error(f"Error creating table: {e}")
            raise

    def insert_data(self, file_path: str) -> Tuple[bool, str, Dict[str, float]]:
        """Insert data from CSV/Excel file into the database."""
        try:
            df = pd.read_csv(file_path) if file_path.endswith(".csv") else pd.read_excel(file_path)
            self.create_table_from_df(df)  # Ensure table structure matches data

            df.to_sql("resumes", self.conn, if_exists="replace", index=False)

            self.logger.info(f"Inserted {len(df)} records")
            return True, f"Inserted {len(df)} records", {}
        except Exception as e:
            self.logger.error(f"Error inserting data: {e}")
            return False, f"Error inserting data: {str(e)}", {}

    def search_resumes(self, filters: Dict[str, Union[str, tuple, List[str]]]) -> pd.DataFrame:
        """Search resumes based on filters."""
        try:
            query = "SELECT * FROM resumes WHERE 1=1"
            params = []

            for column, value in filters.items():
                if value:
                    if isinstance(value, tuple):  # Range filter
                        query += f' AND "{column}" BETWEEN ? AND ?'
                        params.extend(value)
                    elif isinstance(value, list):  # Multi-value filter
                        query += f' AND "{column}" IN ({",".join(["?"] * len(value))})'
                        params.extend(value)
                    else:  # Text search
                        query += f' AND LOWER("{column}") LIKE LOWER(?)'
                        params.append(f"%{value}%")

            return pd.read_sql_query(query, self.conn, params=params)
        except Exception as e:
            self.logger.error(f"Error searching resumes: {e}")
            return pd.DataFrame()
        
    def get_all_users(self):
        """Retrieve all users from the database, including their emails."""
        try:
            self.cursor.execute("SELECT id, username, email FROM users")  # ✅ Fetch email too
            users = self.cursor.fetchall()

            return [{"id": row[0], "username": row[1], "email": row[2]} for row in users]  # ✅ Include email
        except Exception as e:
            print(f"❌ Error fetching users: {e}")
            return []



    def get_user(self, username: str) -> Union[dict, None]:
        """Retrieve a user from the database by username."""
        try:
            self.cursor.execute("SELECT id, username, password, email FROM users WHERE username = ?", (username,))
            row = self.cursor.fetchone()

            if row:
                return {"id": row[0], "username": row[1], "password": row[2], "email": row[3]}  # ✅ Includes password # ✅ Includes ID for session tracking

            return None  # ✅ Explicitly return None if user not found

        except Exception as e:
            self.logger.error(f"❌ Error fetching user: {e}")
            return None  # ✅ Return None in case of an error

    def get_admin(self, username: str) -> Union[dict, None]:
        """Retrieve an admin user from the database by username."""
        try:
            self.cursor.execute("SELECT username, password FROM users WHERE username = ? AND role = 'admin'", (username,))
            row = self.cursor.fetchone()
            return {"username": row[0], "password": row[1]} if row else None
        except Exception as e:
            self.logger.error(f"Error fetching admin: {e}")
            return None
    def add_user(self, username, password, email):
        """Add a regular user to the database."""
        if not email:
            print("❌ Debug: Email is missing for user!")
            return False  # Prevent insertion if email is missing

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")  # ✅ Hash password
        try:
            self.cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                                (username, hashed_password, email))
            self.conn.commit()
            print(f"✅ Debug: User '{username}' added to SQL DB with email '{email}'")
            return True
        except Exception as e:
            print(f"❌ Error inserting user into SQL: {e}")
            return False


# Initialize the database when this file is imported
db = Database()
