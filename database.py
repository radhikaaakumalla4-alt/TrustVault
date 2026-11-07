
import sqlite3
from werkzeug.security import generate_password_hash


def create_database():

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    # Users Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
    """)

    # Default Users
    users = [
        ("admin", "Admin@123", "admin"),
        ("owner", "Owner@123", "owner"),
        ("viewer", "Viewer@123", "viewer")
    ]

    for username, password, role in users:

        hashed_password = generate_password_hash(password)

        cur.execute("""
            INSERT OR IGNORE INTO users
            (username, password, role)
            VALUES (?, ?, ?)
        """, (username, hashed_password, role))

    # Documents Table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner TEXT NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    con.commit()
    con.close()


if __name__ == "__main__":

    create_database()

    print("Database Created Successfully!")


