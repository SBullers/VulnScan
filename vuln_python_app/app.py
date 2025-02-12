# vuln_python_app/app.py
from flask import Flask, request, render_template_string, jsonify
import jwt
import yaml
from sqlalchemy import create_engine, text

app = Flask(__name__)
app.secret_key = "super_secret_key_123"  # Hardcoded secret

# Vulnerable database connection
engine = create_engine("sqlite:///app.db")

# Create a simple table
with engine.connect() as conn:
    conn.execute(
        text(
            """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        )
    """
        )
    )
    # Add some test data
    conn.execute(
        text(
            "INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'admin', 'secret')"
        )
    )


@app.route("/")
def home():
    # Vulnerable template - SSTI
    template = """
    <h1>Welcome to Vulnerable Python App</h1>
    <p>Hello, {}</p>
    """.format(
        request.args.get("name", "Guest")
    )
    return render_template_string(template)


@app.route("/api/auth")
def auth():
    # Vulnerable JWT implementation
    username = request.args.get("username", "")
    token = jwt.encode({"user": username}, "weak_secret", algorithm="HS256")
    return jsonify({"token": token})


@app.route("/api/data")
def get_data():
    # Vulnerable YAML parsing
    user_data = request.args.get("data", "")
    try:
        parsed_data = yaml.load(user_data, Loader=yaml.Loader)  # Unsafe loader
        return jsonify(parsed_data)
    except Exception as e:
        return str(e)


@app.route("/api/users")
def get_user():
    # SQL Injection vulnerability
    username = request.args.get("username", "")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    with engine.connect() as conn:
        result = conn.execute(text(query))
        users = [dict(row) for row in result]
    return jsonify(users)


@app.route("/requirements.txt")
def requirements():
    # Exposed requirements file
    with open("requirements.txt", "r") as f:
        return f.read()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)  # Debug mode enabled in production
