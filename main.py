from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

#CONFIGURE FLASK-LOGIN
login_manager = LoginManager()
login_manager.init_app(app)
# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE DATABASE


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# CREATE TABLE IN DB

#UserMixin is the class of Flask-Login
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("register.html")
    else:
        # Werkzeug;
        hashed_pass = generate_password_hash(request.form.get('password'),method='scrypt', salt_length=12)
        new_user = User(
            email=request.form.get('email'),
            password=hashed_pass,
            name=request.form.get('name')
        )
        # DB: OK
        try:
            db.session.add(new_user)
            db.session.commit()
            # Flask-Login: Log in and authenticate user after adding details to database.
            login_user(new_user)
            return redirect(url_for('secrets'))
        except Exception as error:
            flash('User already exists')
            return redirect(url_for("register"))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        # DB: Find user by email entered.
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        # Werkzeug: Check stored password hash against entered password hashed.
        print(check_password_hash(user.password, password))
        if check_password_hash(user.password, password):
            # Flask-Login
            login_user(user)
            return redirect(url_for('secrets'))

    return render_template("login.html")


@app.route('/secrets')
#This decorator comes from Flask-Login
@login_required
def secrets():
    print(current_user.name)
    # Flask-Login: Passing the name from the current_user
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
def logout():
    # Flask - Login
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
#This decorator comes from Flask-Login
@login_required
def download():
    return send_from_directory(
        'static', 'files/cheat_sheet.pdf', as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)
