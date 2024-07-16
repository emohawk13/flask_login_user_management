from models import User

def get_user_full_name(session):
    if "user_id" in session:
        user_id = session["user_id"]
        user = User.query.get(user_id)
        if user:
            return f"{user.f_name} {user.l_name}"
    return None
