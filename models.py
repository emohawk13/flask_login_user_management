from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import os
import bcrypt

db = SQLAlchemy()

def start_db(app):
    db.init_app(app)
    if not os.path.exists('db.db'):
        open('db.db', 'w').close()
        print("Created new database file 'db.db'.")
    with app.app_context():
        db.create_all()
        print("Database has been initialized.")
        insert_admin()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    active = db.Column(db.Integer)
    username = db.Column(db.String(200), unique=True)
    f_name = db.Column(db.String(20), unique=True)
    l_name = db.Column(db.String(30))
    email = db.Column(db.String(200), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(4))

def insert_admin():
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        password ='password1234'
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        new_user = User(
            active=1,
            username='admin',
            f_name='Admin',
            l_name='',
            email='admin@example.com',
            password=hashed_password,
            role='admin'
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            print('Admin user inserted successfully.')
        except Exception as e:
            db.session.rollback()
            print(f'Error inserting admin user: {str(e)}')
