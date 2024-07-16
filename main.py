from flask import (Flask,redirect,render_template,request,jsonify,abort,current_app,session,flash)
from flask_login import (LoginManager,login_required,login_user,logout_user,current_user)
from flask_scss import Scss
import logging
import requests
from functools import wraps
import bcrypt
from models import start_db, User, db
from utils import get_user_full_name

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.db"
app.config["SECRET_KEY"] = "619619"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
start_db(app)

Scss(app)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

login_manager = LoginManager()
login_manager.init_app(app)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return current_app.login_manager.unauthorized()
        if current_user.role != "admin":
            abort(403)  # Forbidden
        return f(*args, **kwargs)

    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/", methods=["GET"])
@login_required
def get_home():
    return render_template("login.html")

@app.route("/login", methods=["GET"])
def get_login():
    return render_template("login.html")

@app.route("/signup", methods=["GET"])
def get_signup():
    return render_template("signup.html")

@app.route("/logout", methods=["GET"])
def logout():
    logout_user()
    return redirect("/login")

@app.route("/user_status_form", methods=["POST"])
def user_status_form():
    full_name = get_user_full_name(session)
    return render_template("user_status.html", full_name=full_name)

@app.route('/change_password', methods=['GET'])
@login_required
def get_change_password():
    full_name = get_user_full_name(session)
    return render_template('ch_password.html', full_name=full_name)

@app.route("/home", methods=["GET"])
def get_home_logged_in():
    if "user_id" in session:
        user_id = session["user_id"]
        user = User.query.get(user_id)
        if user:
            full_name = f"{user.f_name} {user.l_name}"
            return render_template("home.html", full_name=full_name)
    return "User not logged in"

@app.route("/login", methods=["POST"])
def login_post():
    email = request.form["email"]
    password = request.form["password"]
    user = User.query.filter_by(email=email).first()
    if user and bcrypt.checkpw(password.encode("utf-8"), user.password.encode("utf-8")):
        login_user(user)
        session["user_id"] = user.id
        return redirect("/home")
    return render_template("error.html", error_msg="Invalid email or password"), 401

@app.route("/signup", methods=["POST"])
def signup_post():
    username = request.form["username"]
    email = request.form["email"]
    password = request.form["password"]
    f_name = request.form["f_name"]
    l_name = request.form["l_name"]
    active_status = 1
    role = "user"
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
        "utf-8"
    )
    user = User(
        username=username,
        email=email,
        password=hashed_password,
        active=active_status,
        f_name=f_name,
        l_name=l_name,
        role=role,
    )
    db.session.add(user)
    db.session.commit()
    return redirect("/users")

@app.route("/user_status", methods=["GET", "POST"])
def user_status():
    full_name = get_user_full_name(session)
    if request.method == "GET":
        return render_template("user_status.html", full_name=full_name)

    username = request.form.get("username")
    email = request.form.get("email")
    f_name = request.form.get("f_name")
    l_name = request.form.get("l_name")
    action = request.form.get("action")
    status = request.form.get("status")
    query = User.query
    if username:
        query = query.filter_by(username=username)
    if email:
        query = query.filter_by(email=email)
    if f_name:
        query = query.filter_by(f_name=f_name)
    if l_name:
        query = query.filter_by(l_name=l_name)
    user = query.first()

    if user:
        try:
            if action == "activate":
                user.active = 1
            elif action == "deactivate":
                user.active = 0
            else:
                return (
                    render_template("error.html", error_msg="Invalid action for 'active' status"),400,)

            if status == "admin":
                user.role = "admin"
            elif status == "user":
                user.role = "user"
            else:
                return (
                    render_template("error.html", error_msg="Invalid action for 'role' status"),400,)

            db.session.commit()
            return redirect("/users")
        except Exception as e:
            app.logger.error(f"Error updating user status: {str(e)}")
            return (
                render_template("error.html",error_msg="An error occurred while processing your request",),500,)

    return render_template("error.html", error_msg="User not found"), 404

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old_password = request.form['old_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if not bcrypt.checkpw(old_password.encode('utf-8'), current_user.password.encode('utf-8')):
        flash('Incorrect old password. Please try again.', 'error')
        return redirect('/change_password')
    if new_password != confirm_password:
        flash('New password and confirmation do not match. Please try again.', 'error')
        return redirect('/change_password')
    
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    current_user.password = hashed_password
    db.session.commit()

    flash('Password updated successfully.', 'success')
    return redirect('/home') 

@app.route("/users", methods=["GET"])
def render_user_list():
    api_url = "http://localhost:5000/api/users"
    full_name = get_user_full_name(session)
    try:
        response = requests.get(api_url)
        response.raise_for_status()
        users = response.json()["users"]
        active_users = [user for user in users if user["active"] == 1]
        inactive_users = [user for user in users if user["active"] == 0]
        return render_template(
            "user_management.html", full_name=full_name,
            active_users=active_users,
            inactive_users=inactive_users,
        )
    except requests.exceptions.HTTPError as http_err:
        app.logger.error(f"HTTP error occurred: {http_err}")
        return (
            render_template("error.html", error_msg="HTTP error occurred. Please try again later."),500,)
    except requests.exceptions.RequestException as req_err:
        app.logger.error(f"Request error occurred: {req_err}")
        return (
            render_template("error.html",error_msg="Request error occurred. Please try again later.",),500,)
    except (KeyError, ValueError) as json_err:
        app.logger.error(f"Error decoding JSON: {json_err}")
        return (
            render_template("error.html",error_msg="Error decoding JSON response. Please try again later.",),500,)

@app.route("/api/users", methods=["GET"])
def get_users():
    users = User.query.all()
    user_list = []
    for user in users:
        capitalized_role = user.role.capitalize()
        user_data = {
            "id": user.id,
            "active": user.active,
            "username": user.username,
            "name": f"{user.f_name} {user.l_name}",
            "role": capitalized_role,
        }
        user_list.append(user_data)
    return jsonify({"users": user_list})

if __name__ == "__main__":
    app.run(debug=True)
