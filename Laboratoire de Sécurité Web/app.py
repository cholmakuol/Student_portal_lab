import os
import re
import sqlite3
import sys
import uuid
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, redirect, render_template, request, send_from_directory,
    session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
UPLOAD_DIR = BASE_DIR / "uploads"
DB_PATH = INSTANCE_DIR / "student_portal.db"
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt"}
MAX_UPLOAD_BYTES = 2 * 1024 * 1024

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-secret-key"),
    DATABASE=str(DB_PATH),
    UPLOAD_FOLDER=str(UPLOAD_DIR),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Keep this app local. Do not deploy the vulnerable routes on the internet.


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(reset=False):
    INSTANCE_DIR.mkdir(exist_ok=True)
    UPLOAD_DIR.mkdir(exist_ok=True)
    if reset and DB_PATH.exists():
        DB_PATH.unlink()

    db = sqlite3.connect(DB_PATH)
    cur = db.cursor()
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_plain TEXT,
            password_hash TEXT,
            role TEXT NOT NULL DEFAULT 'student',
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            bio TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL,
            title TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            grade TEXT DEFAULT 'N/A',
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            mode TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            username TEXT,
            ip_address TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        );
        """
    )

    existing = cur.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if existing == 0:
        users = [
            ("admin", "admin123", generate_password_hash("Admin@12345"), "admin", "Administrateur Système", "admin@student.local", "Compte administrateur pour la démonstration."),
            ("chol", "chol123", generate_password_hash("Chol@12345"), "student", "Chol Makuol Garang Thok", "chol@student.local", "Auteur du projet et étudiant en Sécurité Informatique et Réseau."),
            ("youssef", "youssef123", generate_password_hash("Youssef@12345"), "student", "Youssef Bissakri", "youssef@student.local", "Étudiant en Sécurité Informatique et Réseau."),
            ("mustapha", "mustapha123", generate_password_hash("Mustapha@12345"), "student", "Mustapha Ouchna", "mustapha@student.local", "Étudiant en Sécurité Informatique et Réseau."),
            ("yassine", "yassine123", generate_password_hash("Yassine@12345"), "student", "Yassine ETTAHIRI", "yassine@student.local", "Étudiant en Sécurité Informatique et Réseau."),
            ("abderrahmane", "abderrahmane123", generate_password_hash("Abderrahmane@12345"), "student", "Abderrahmane Bouirig", "abderrahmane@student.local", "Étudiant en Sécurité Informatique et Réseau."),
            ("abdelkhalk", "abdelkhalk123", generate_password_hash("Abdelkhalk@12345"), "student", "Abdelkhalk Ait Elborj", "abdelkhalk@student.local", "Étudiant en Sécurité Informatique et Réseau."),
            ("soulaimane", "soulaimane123", generate_password_hash("Soulaimane@12345"), "student", "Soulaimane Saghir", "soulaimane@student.local", "Étudiant en Sécurité Informatique et Réseau."),
        ]
        cur.executemany(
            "INSERT INTO users(username, password_plain, password_hash, role, full_name, email, bio) VALUES (?, ?, ?, ?, ?, ?, ?)",
            users,
        )
        courses = [
            ("SIR401", "Sécurité des Applications Web", 2, "A"),
            ("SIR402", "Audit et Test d’Intrusion", 2, "A-"),
            ("SIR401", "Sécurité des Applications Web", 3, "A"),
            ("SIR403", "Sécurité Réseau", 3, "B+"),
            ("SIR404", "Cryptographie Appliquée", 4, "B"),
            ("SIR405", "Administration Système Sécurisée", 4, "A-"),
            ("SIR406", "Détection d’Intrusion", 5, "B+"),
            ("SIR407", "Sécurité Cloud", 5, "B"),
            ("SIR408", "Forensic Numérique", 6, "A-"),
            ("SIR409", "Gestion des Risques", 6, "B+"),
            ("SIR410", "Sécurité Wi-Fi", 7, "B"),
            ("SIR411", "Pare-feu et VPN", 7, "A-"),
            ("SIR412", "DevSecOps", 8, "B+"),
            ("SIR413", "Supervision SIEM", 8, "A"),
        ]
        cur.executemany("INSERT INTO courses(code, title, owner_id, grade) VALUES (?, ?, ?, ?)", courses)
        cur.execute(
            "INSERT INTO comments(user_id, body, created_at) VALUES (?, ?, ?)",
            (2, "Bienvenue dans le laboratoire du portail étudiant EST Guelmim.", datetime.utcnow().isoformat()),
        )
    db.commit()
    db.close()


def log_event(event_type, username=None, details=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs(event_type, username, ip_address, details, created_at) VALUES (?, ?, ?, ?, ?)",
        (event_type, username, request.remote_addr, details, datetime.utcnow().isoformat()),
    )
    db.commit()


@app.before_request
def ensure_db_exists():
    if not DB_PATH.exists():
        init_db(reset=False)


@app.after_request
def add_security_headers(response):
    # These headers protect the secure side. They intentionally do not fix vulnerable code logic.
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if request.path.startswith("/secure"):
        response.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'")
    return response


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def login_required(mode=None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Veuillez vous connecter d’abord.", "warning")
                target = "vuln_login" if mode == "vuln" else "secure_login"
                return redirect(url_for(target))
            if mode and session.get("mode") != mode:
                flash("Veuillez vous connecter au bon mode du laboratoire.", "warning")
                target = "vuln_login" if mode == "vuln" else "secure_login"
                return redirect(url_for(target))
            return view(*args, **kwargs)
        return wrapped
    return decorator


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("secure_login"))
        if session.get("role") != "admin":
            log_event("ACCESS_DENIED", session.get("username"), "Tentative d’accès admin par un utilisateur non-admin")
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/")
def index():
    return render_template("index.html", user=current_user())


@app.route("/logout")
def logout():
    session.clear()
    flash("Déconnexion réussie.", "info")
    return redirect(url_for("index"))


# -----------------------------
# Vulnerable training section
# -----------------------------
@app.route("/vuln/login", methods=["GET", "POST"])
def vuln_login():
    last_query = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # VULNERABLE: string formatting in SQL allows SQL injection.
        query = f"SELECT * FROM users WHERE username = '{username}' AND password_plain = '{password}'"
        last_query = query
        try:
            user = get_db().execute(query).fetchone()
        except sqlite3.Error as exc:
            flash(f"Erreur SQL : {exc}", "danger")
            user = None
        if user:
            session.clear()
            session.update(user_id=user["id"], username=user["username"], role=user["role"], mode="vuln")
            flash("Connexion vulnérable réussie.", "success")
            return redirect(url_for("vuln_dashboard"))
        flash("Identifiants invalides.", "danger")
    return render_template("vuln_login.html", last_query=last_query)


@app.route("/vuln/register", methods=["GET", "POST"])
def vuln_register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        full_name = request.form.get("full_name", "")
        email = request.form.get("email", "")
        bio = request.form.get("bio", "")
        try:
            # VULNERABLE DESIGN: stores plaintext password for the vulnerable demo.
            get_db().execute(
                "INSERT INTO users(username, password_plain, password_hash, role, full_name, email, bio) VALUES (?, ?, ?, 'student', ?, ?, ?)",
                (username, password, generate_password_hash(password), full_name, email, bio),
            )
            get_db().commit()
            flash("Inscription terminée. Essayez la connexion vulnérable.", "success")
            return redirect(url_for("vuln_login"))
        except sqlite3.IntegrityError:
            flash("Ce nom d’utilisateur existe déjà.", "danger")
    return render_template("vuln_register.html")


@app.route("/vuln/dashboard")
@login_required("vuln")
def vuln_dashboard():
    db = get_db()
    courses = db.execute("SELECT * FROM courses WHERE owner_id = ?", (session["user_id"],)).fetchall()
    comments = db.execute(
        "SELECT comments.*, users.username FROM comments JOIN users ON users.id = comments.user_id ORDER BY comments.id DESC"
    ).fetchall()
    return render_template("vuln_dashboard.html", courses=courses, comments=comments, user=current_user())


@app.route("/vuln/profile")
@login_required("vuln")
def vuln_profile():
    # VULNERABLE: IDOR. Any logged-in user can change ?id= and view another profile.
    user_id = request.args.get("id", session.get("user_id"))
    query = f"SELECT * FROM users WHERE id = {user_id}"
    try:
        user = get_db().execute(query).fetchone()
    except sqlite3.Error as exc:
        flash(f"Erreur SQL : {exc}", "danger")
        user = None
    if not user:
        abort(404)
    courses = get_db().execute("SELECT * FROM courses WHERE owner_id = ?", (user["id"],)).fetchall()
    return render_template("vuln_profile.html", profile=user, courses=courses, raw_query=query)


@app.route("/vuln/search")
@login_required("vuln")
def vuln_search():
    q = request.args.get("q", "")
    results = []
    raw_query = None
    if q:
        # VULNERABLE: SQL injection in LIKE clause.
        raw_query = f"SELECT id, code, title, grade FROM courses WHERE title LIKE '%{q}%' OR code LIKE '%{q}%'"
        try:
            results = get_db().execute(raw_query).fetchall()
        except sqlite3.Error as exc:
            flash(f"Erreur SQL : {exc}", "danger")
    return render_template("vuln_search.html", q=q, results=results, raw_query=raw_query)


@app.route("/vuln/comment", methods=["POST"])
@login_required("vuln")
def vuln_comment():
    body = request.form.get("body", "")
    get_db().execute(
        "INSERT INTO comments(user_id, body, created_at) VALUES (?, ?, ?)",
        (session["user_id"], body, datetime.utcnow().isoformat()),
    )
    get_db().commit()
    flash("Commentaire ajouté.", "success")
    return redirect(url_for("vuln_dashboard"))


@app.route("/vuln/upload", methods=["GET", "POST"])
@login_required("vuln")
def vuln_upload():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or f.filename == "":
            flash("Aucun fichier sélectionné.", "warning")
            return redirect(request.url)
        # VULNERABLE: accepts any extension and keeps the original name.
        filename = secure_filename(f.filename)
        path = UPLOAD_DIR / filename
        f.save(path)
        get_db().execute(
            "INSERT INTO uploads(user_id, original_name, stored_name, mode, uploaded_at) VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], f.filename, filename, "vuln", datetime.utcnow().isoformat()),
        )
        get_db().commit()
        flash("Fichier uploadé avec le gestionnaire vulnérable.", "success")
    files = get_db().execute("SELECT * FROM uploads WHERE mode = 'vuln' ORDER BY id DESC").fetchall()
    return render_template("vuln_upload.html", files=files)


@app.route("/vuln/admin")
@login_required("vuln")
def vuln_admin():
    # VULNERABLE: broken access control. Any logged-in user can access this.
    users = get_db().execute("SELECT id, username, role, full_name, email, password_plain FROM users ORDER BY id").fetchall()
    logs = get_db().execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 20").fetchall()
    return render_template("vuln_admin.html", users=users, logs=logs)


# -----------------------------
# Secure implementation section
# -----------------------------
@app.route("/secure/login", methods=["GET", "POST"])
def secure_login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and user["password_hash"] and check_password_hash(user["password_hash"], password):
            session.clear()
            session.update(user_id=user["id"], username=user["username"], role=user["role"], mode="secure")
            log_event("LOGIN_SUCCESS", username, "Connexion sécurisée réussie")
            flash("Connexion sécurisée réussie.", "success")
            return redirect(url_for("secure_dashboard"))
        log_event("LOGIN_FAILED", username, "Tentative de connexion sécurisée invalide")
        flash("Identifiants invalides.", "danger")
    return render_template("secure_login.html")


@app.route("/secure/register", methods=["GET", "POST"])
def secure_register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip()
        bio = request.form.get("bio", "").strip()

        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
            flash("Le nom d’utilisateur doit contenir 3 à 30 caractères : lettres, chiffres, point, underscore ou tiret uniquement.", "danger")
            return render_template("secure_register.html")
        if len(password) < 10 or not re.search(r"[A-Z]", password) or not re.search(r"[a-z]", password) or not re.search(r"\d", password):
            flash("Le mot de passe doit contenir au moins 10 caractères avec majuscule, minuscule et chiffre.", "danger")
            return render_template("secure_register.html")
        try:
            get_db().execute(
                "INSERT INTO users(username, password_plain, password_hash, role, full_name, email, bio) VALUES (?, NULL, ?, 'student', ?, ?, ?)",
                (username, generate_password_hash(password), full_name, email, bio),
            )
            get_db().commit()
            log_event("REGISTER", username, "Inscription sécurisée")
            flash("Inscription sécurisée terminée. Vous pouvez vous connecter maintenant.", "success")
            return redirect(url_for("secure_login"))
        except sqlite3.IntegrityError:
            flash("Ce nom d’utilisateur existe déjà.", "danger")
    return render_template("secure_register.html")


@app.route("/secure/dashboard")
@login_required("secure")
def secure_dashboard():
    db = get_db()
    courses = db.execute("SELECT * FROM courses WHERE owner_id = ?", (session["user_id"],)).fetchall()
    comments = db.execute(
        "SELECT comments.*, users.username FROM comments JOIN users ON users.id = comments.user_id ORDER BY comments.id DESC"
    ).fetchall()
    return render_template("secure_dashboard.html", courses=courses, comments=comments, user=current_user())


@app.route("/secure/profile")
@login_required("secure")
def secure_profile():
    requested_id = request.args.get("id", str(session.get("user_id")))
    try:
        requested_id_int = int(requested_id)
    except ValueError:
        abort(400)

    # FIXED: enforce object-level authorization.
    if session.get("role") != "admin" and requested_id_int != session.get("user_id"):
        log_event("IDOR_BLOCKED", session.get("username"), f"Tentative d’accès au profil id {requested_id_int}")
        abort(403)

    user = get_db().execute("SELECT * FROM users WHERE id = ?", (requested_id_int,)).fetchone()
    if not user:
        abort(404)
    courses = get_db().execute("SELECT * FROM courses WHERE owner_id = ?", (user["id"],)).fetchall()
    return render_template("secure_profile.html", profile=user, courses=courses)


@app.route("/secure/search")
@login_required("secure")
def secure_search():
    q = request.args.get("q", "").strip()
    results = []
    if q:
        pattern = f"%{q}%"
        # FIXED: parameterized query prevents SQL injection.
        results = get_db().execute(
            "SELECT id, code, title, grade FROM courses WHERE owner_id = ? AND (title LIKE ? OR code LIKE ?)",
            (session["user_id"], pattern, pattern),
        ).fetchall()
    return render_template("secure_search.html", q=q, results=results)


@app.route("/secure/comment", methods=["POST"])
@login_required("secure")
def secure_comment():
    body = request.form.get("body", "").strip()
    if len(body) > 500:
        flash("Le commentaire est trop long.", "danger")
        return redirect(url_for("secure_dashboard"))
    get_db().execute(
        "INSERT INTO comments(user_id, body, created_at) VALUES (?, ?, ?)",
        (session["user_id"], body, datetime.utcnow().isoformat()),
    )
    get_db().commit()
    log_event("COMMENT_CREATED", session.get("username"), "Commentaire sécurisé créé")
    flash("Commentaire ajouté de façon sécurisée.", "success")
    return redirect(url_for("secure_dashboard"))


@app.route("/secure/upload", methods=["GET", "POST"])
@login_required("secure")
def secure_upload():
    if request.method == "POST":
        f = request.files.get("file")
        if not f or f.filename == "":
            flash("Aucun fichier sélectionné.", "warning")
            return redirect(request.url)
        if not allowed_file(f.filename):
            log_event("UPLOAD_BLOCKED", session.get("username"), f"Nom de fichier bloqué {f.filename}")
            flash("Bloqué. Types autorisés : pdf, png, jpg, jpeg, txt.", "danger")
            return redirect(request.url)
        original = secure_filename(f.filename)
        ext = original.rsplit(".", 1)[1].lower()
        stored = f"{uuid.uuid4().hex}.{ext}"
        f.save(UPLOAD_DIR / stored)
        get_db().execute(
            "INSERT INTO uploads(user_id, original_name, stored_name, mode, uploaded_at) VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], original, stored, "secure", datetime.utcnow().isoformat()),
        )
        get_db().commit()
        log_event("UPLOAD_SUCCESS", session.get("username"), f"Uploadé {original}")
        flash("Fichier uploadé avec le gestionnaire sécurisé.", "success")
    files = get_db().execute(
        "SELECT * FROM uploads WHERE mode = 'secure' AND user_id = ? ORDER BY id DESC",
        (session["user_id"],),
    ).fetchall()
    return render_template("secure_upload.html", files=files)


@app.route("/secure/admin")
@login_required("secure")
@admin_required
def secure_admin():
    users = get_db().execute("SELECT id, username, role, full_name, email FROM users ORDER BY id").fetchall()
    logs = get_db().execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50").fetchall()
    return render_template("secure_admin.html", users=users, logs=logs)


@app.route("/uploads/<path:filename>")
@login_required()
def uploaded_file(filename):
    # In a real app, add per-file authorization. Here it supports the lab demo.
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=False)


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="Interdit : accès refusé."), 403


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="Page ou objet introuvable."), 404


@app.errorhandler(400)
def bad_request(_error):
    return render_template("error.html", code=400, message="Requête invalide."), 400


if __name__ == "__main__":
    if "--init-db" in sys.argv:
        init_db(reset=True)
        print(f"Base de données initialisée à {DB_PATH}")
        sys.exit(0)
    init_db(reset=False)
    app.run(host="127.0.0.1", port=5000, debug=True)
