
from flask import Flask, render_template, request, redirect, session, send_from_directory, abort
import sqlite3
import os

from werkzeug.security import check_password_hash,generate_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32)
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
def create_activity_table():
    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        document_id INTEGER,
        action TEXT NOT NULL,
        activity_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    con.commit()
    con.close()


create_activity_table()

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "docx"}
def create_permissions_table():

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS document_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        document_id INTEGER NOT NULL,
        owner TEXT NOT NULL,
        viewer_username TEXT NOT NULL,
        permission TEXT DEFAULT 'view',
        UNIQUE(document_id, viewer_username)
    )
    """)

    con.commit()
    con.close()


create_permissions_table()
def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/")
def home():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    
    cur.execute(
        "SELECT password, role FROM users WHERE username = ?",
        (username,)
    )

    user = cur.fetchone()
    con.close()

    if user and check_password_hash(user[0], password):

        session["username"] = username
        session["role"] = user[1]

        if user[1] == "admin":
            return redirect("/admin")

        elif user[1] == "owner":
            return redirect("/owner")

        elif user[1] == "viewer":
            return redirect("/viewer")

    return "<h2>Invalid Username or Password</h2><a href='/'>Try Again</a>"


@app.route("/admin")
def admin_dashboard():
    if "username" not in session or session.get("role") != "admin":
        return redirect("/")

    return render_template("admin_dashboard.html")
# Admin Manage Users Route
@app.route("/manage_users")
def manage_users():

    if "username" not in session or session.get("role") != "admin":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        SELECT id, username, role
        FROM users
    """)

    users = cur.fetchall()
    con.close()

    return render_template(
        "manage_users.html",
        users=users
    )
# Admin Manage Documents
@app.route("/admin_documents")
def admin_documents():

    if "username" not in session or session.get("role") != "admin":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        SELECT id, original_name, owner, upload_date
        FROM documents
        ORDER BY upload_date DESC
    """)

    documents = cur.fetchall()
    con.close()

    return render_template(
        "admin_documents.html",
        documents=documents
    )
# Admin Delete Document
@app.route("/delete_document/<int:document_id>", methods=["POST"])
def delete_document(document_id):

    if "username" not in session or session.get("role") != "admin":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        SELECT stored_name
        FROM documents
        WHERE id = ?
    """, (document_id,))

    document = cur.fetchone()

    if document is None:
        con.close()
        abort(404)

    # Delete actual file from uploads folder
    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        document[0]
    )

    if os.path.exists(file_path):
        os.remove(file_path)
    # Log Document Deletion
    cur.execute("""
        INSERT INTO activity_logs
        (username, document_id, action)
        VALUES (?, ?, ?)
    """, (
        session["username"],
        document_id,
        "Document Deleted"
    ))

    # Delete document permissions
    cur.execute("""
        DELETE FROM document_permissions
        WHERE document_id = ?
    """, (document_id,))

    # Delete document record
    cur.execute("""
        DELETE FROM documents
        WHERE id = ?
    """, (document_id,))

    con.commit()
    con.close()

    return redirect("/admin_documents")
# Admin Add New User
@app.route("/add_user", methods=["GET", "POST"])
def add_user():

    if "username" not in session or session.get("role") != "admin":
        return redirect("/")

    if request.method == "POST":

        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        if role not in ["owner", "viewer"]:
            return "Invalid role!"

        hashed_password = generate_password_hash(password)

        con = sqlite3.connect("trustvault.db")
        cur = con.cursor()

        try:
            cur.execute("""
                INSERT INTO users (username, password, role)
                VALUES (?, ?, ?)
            """, (username, hashed_password, role))

            con.commit()

        except sqlite3.IntegrityError:
            con.close()
            return "Username already exists!"

        con.close()

        return redirect("/manage_users")

    return render_template("add_user.html")
# Admin Delete User
@app.route("/delete_user/<int:user_id>", methods=["POST"])
def delete_user(user_id):

    if "username" not in session or session.get("role") != "admin":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        SELECT username, role
        FROM users
        WHERE id = ?
    """, (user_id,))

    user = cur.fetchone()

    if user is None:
        con.close()
        abort(404)

    username, role = user

    # Protect admin accounts
    if role == "admin":
        con.close()
        return "Admin account cannot be deleted!"

    # Prevent deleting an owner who has documents
    if role == "owner":
        cur.execute("""
            SELECT id FROM documents
            WHERE owner = ?
        """, (username,))

        if cur.fetchone():
            con.close()
            return "Cannot delete owner. Delete or transfer their documents first!"

    # Record deletion in activity logs
    cur.execute("""
        INSERT INTO activity_logs
        (username, document_id, action)
        VALUES (?, NULL, ?)
    """, (session["username"], "User Deleted: " + username))

    # Remove permissions
    cur.execute("""
        DELETE FROM document_permissions
        WHERE viewer_username = ? OR owner = ?
    """, (username, username))

    # Delete user
    cur.execute("""
        DELETE FROM users
        WHERE id = ?
    """, (user_id,))

    con.commit()
    con.close()

    return redirect("/manage_users")
@app.route("/activity_logs")
def activity_logs():

    if "username" not in session or session.get("role") != "admin":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        SELECT username, document_id, action, activity_time
        FROM activity_logs
        ORDER BY activity_time DESC
    """)

    logs = cur.fetchall()
    con.close()

    return render_template("activity_logs.html", logs=logs)
@app.route("/owner")
def owner_dashboard():
    if "username" not in session or session.get("role") != "owner":
        return redirect("/")

    return render_template("owner_dashboard.html")


@app.route("/viewer")
def viewer_dashboard():
    if "username" not in session or session.get("role") != "viewer":
        return redirect("/")

    return render_template("viewer_dashboard.html")
# Viewer Documents Route
@app.route("/viewer_documents")
def viewer_documents():

    if "username" not in session or session.get("role") != "viewer":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        SELECT documents.id,
               documents.original_name,
               documents.owner
        FROM documents
        JOIN document_permissions
        ON documents.id = document_permissions.document_id
        WHERE document_permissions.viewer_username = ?
        AND document_permissions.permission = 'view'
    """, (session["username"],))

    documents = cur.fetchall()
    con.close()

    return render_template(
        "viewer_documents.html",
        documents=documents
    )
# Viewer Secure Download Route
@app.route("/viewer_download/<int:document_id>")
def viewer_download(document_id):

    if "username" not in session or session.get("role") != "viewer":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        SELECT documents.stored_name,
               documents.original_name
        FROM documents
        JOIN document_permissions
        ON documents.id = document_permissions.document_id
        WHERE documents.id = ?
        AND document_permissions.viewer_username = ?
        AND document_permissions.permission = 'view'
    """, (document_id, session["username"]))

    document = cur.fetchone()

    if document is None:
        con.close()
        abort(404)

    cur.execute("""
        INSERT INTO activity_logs
        (username, document_id, action)
        VALUES (?, ?, ?)
    """, (session["username"], document_id, " Viewer Document Downloaded"))

    con.commit()
    con.close()

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document[0],
        as_attachment=True,
        download_name=document[1]
    )
@app.route("/upload", methods=["GET", "POST"])
def upload_file():

    if "username" not in session or session.get("role") != "owner":
        return redirect("/")

    if request.method == "POST":

        if "file" not in request.files:
            return "No file selected"

        file = request.files["file"]

        if file.filename == "":
            return "Please select a file"

        if file and allowed_file(file.filename):

            original_name = secure_filename(file.filename)

            # Create unique filename to avoid overwriting
            import uuid
            stored_name = str(uuid.uuid4()) + "_" + original_name

            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

            file.save(
                os.path.join(app.config["UPLOAD_FOLDER"], stored_name)
            )

            # Save document details in database
            con = sqlite3.connect("trustvault.db")
            cur = con.cursor()

            cur.execute("""
                INSERT INTO documents
                (owner, original_name, stored_name)
                VALUES (?, ?, ?)
            """, (
                session["username"],
                original_name,
                stored_name
            ))

            con.commit()
            con.close()

            return "File uploaded successfully!"

        return "Invalid file type"

    return render_template("upload.html")
@app.route("/my_documents")
def my_documents():

    if "username" not in session or session.get("role") != "owner":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        SELECT id, original_name, upload_date
        FROM documents
        WHERE owner = ?
        ORDER BY upload_date DESC
    """, (session["username"],))

    documents = cur.fetchall()

    con.close()

    return render_template(
        "my_documents.html",
        documents=documents
    )

# Share Documents - Give access to Viewer
@app.route("/share_documents", methods=["GET", "POST"])
def share_documents():
    

    if "username" not in session or session.get("role") != "owner":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    if request.method == "POST":

        document_id = request.form["document_id"]
        viewer_username = request.form["viewer_username"]

        cur.execute("""
            SELECT id FROM documents
            WHERE id = ? AND owner = ?
        """, (document_id, session["username"]))

        document = cur.fetchone()

        cur.execute("""
            SELECT username FROM users
            WHERE username = ? AND role = 'viewer'
        """, (viewer_username,))

        viewer = cur.fetchone()

        if document and viewer:
            cur.execute("""
                INSERT OR IGNORE INTO document_permissions
                (document_id, owner, viewer_username, permission)
                VALUES (?, ?, ?, 'view')
            """, (document_id, session["username"], viewer_username))

            con.commit()
            message = "Permission added successfully!"
        else:
            message = "Invalid document or viewer username!"

        cur.execute("""
            SELECT id, original_name FROM documents
            WHERE owner = ?
        """, (session["username"],))

        documents = cur.fetchall()
        con.close()

        return render_template(
            "share_documents.html",
            documents=documents,
            message=message
        )

    cur.execute("""
        SELECT id, original_name FROM documents
        WHERE owner = ?
    """, (session["username"],))

    documents = cur.fetchall()
    con.close()

    return render_template(
        "share_documents.html",
        documents=documents
    )


@app.route("/manage_permissions")
def manage_permissions():

    if "username" not in session or session.get("role") != "owner":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    # Get owner's documents
    cur.execute("""
        SELECT id, original_name FROM documents
        WHERE owner = ?
    """, (session["username"],))

    documents = cur.fetchall()

    # Get existing permissions
    cur.execute("""
        SELECT dp.document_id, d.original_name,
               dp.viewer_username, dp.permission
        FROM document_permissions dp
        JOIN documents d ON dp.document_id = d.id
        WHERE dp.owner = ?
    """, (session["username"],))

    permissions = cur.fetchall()

    con.close()

    return render_template(
        "manage_permissions.html",
        documents=documents,
        permissions=permissions
    )

# Revoke Document Permission

@app.route("/revoke_permission", methods=["POST"])
def revoke_permission():

    if "username" not in session or session.get("role") != "owner":
        return redirect("/")

    document_id = request.form["document_id"]
    viewer_username = request.form["viewer_username"]

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    # Delete document permission
    cur.execute("""
        DELETE FROM document_permissions
        WHERE document_id = ?
        AND viewer_username = ?
        AND owner = ?
    """, (document_id, viewer_username, session["username"]))

    if cur.rowcount > 0:

        # Record revoke activity
        cur.execute("""
            INSERT INTO activity_logs
            (username, document_id, action)
            VALUES (?, ?, ?)
        """, (
            session["username"],
            document_id,
            "Document Permission Revoked"
        ))

    con.commit()
    con.close()

    return redirect("/manage_permissions")


       
@app.route("/download/<int:document_id>")
def download_document(document_id):

    if "username" not in session or session.get("role") != "owner":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        SELECT stored_name, original_name
        FROM documents
        WHERE id = ? AND owner = ?
    """, (document_id, session["username"]))

    document = cur.fetchone()
    con.close()

    if document is None:
        abort(404)
        # Save download activity
    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        INSERT INTO activity_logs
        (username, document_id, action)
        VALUES (?, ?, ?)
    """, (
        session["username"],
        document_id,
        "Document Downloaded"
    ))

    con.commit()
    con.close()    


    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document[0],
        as_attachment=True,
        download_name=document[1]
    )  


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/admin_permissions")
def admin_permissions():

    if "username" not in session or session.get("role") != "admin":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        SELECT document_id, owner, viewer_username, permission
        FROM document_permissions
        ORDER BY id DESC
    """)

    permissions = cur.fetchall()
    con.close()

    return render_template(
        "admin_permissions.html",
        permissions=permissions
    )

@app.route("/admin_view_document/<int:document_id>")
def admin_view_document(document_id):

    if "username" not in session or session.get("role") != "admin":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        SELECT stored_name, original_name
        FROM documents
        WHERE id = ?
    """, (document_id,))

    document = cur.fetchone()
    con.close()

    if document is None:
        return "Document not found", 404

    return render_template(
        "admin_view_document.html",
        document=(document[0], document[1], document_id)
    )
@app.route("/admin_document_file/<int:document_id>")
def admin_document_file(document_id):

    if "username" not in session or session.get("role") != "admin":
        return redirect("/")

    con = sqlite3.connect("trustvault.db")
    cur = con.cursor()

    cur.execute("""
        SELECT stored_name, original_name
        FROM documents
        WHERE id = ?
    """, (document_id,))

    document = cur.fetchone()
    con.close()

    if document is None:
        return "Document not found", 404

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document[0],
        as_attachment=False,
        download_name=document[1]
    )

if __name__ == "__main__":
    app.run(debug=True)