from os import urandom
from flask import Flask, render_template, redirect, url_for, flash, request
from flask_mail import Mail, Message
from flask_login import LoginManager, login_required, login_user, current_user, logout_user
from wtforms import Form, StringField, validators, SubmitField, PasswordField
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash

app = Flask(__name__)
app.secret_key = urandom(16)
mail = Mail()
mail.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./database.sqlite'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    """An admin user capable of viewing reports.

    :param str name: name address of user
    :param str password: encrypted password for the user

    """
    __tablename__ = 'user'

    name = db.Column(db.String, primary_key=True)
    password = db.Column(db.String)
    authenticated = db.Column(db.Boolean, default=False)

    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        """Return the name address to satisfy Flask-Login's requirements."""
        return self.name

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

    def __repr__(self):
        return '<User %r>' % self.name

class LoginForm(Form):
    username = StringField('name', validators=[validators.required()], render_kw={'placeholder':'Nom'})
    password = PasswordField('password', validators=[validators.required()], render_kw={'placeholder':'Mot de passe'})
    submit = SubmitField('submit', render_kw={'value': 'Connexion'})

@login_manager.user_loader
def load_user(user_id): return User.query.get(user_id)

@app.route('/')
def default(): return render_template('index.html')

@app.route('/index.html')
def index(): return render_template('index.html')

@app.route('/email.html')
def email():
    #msg = Message("Hello",
    #        sender="website",
    #        recipients=["brahim.pro@protonmail.com"])
    #msg.body = "testing"
    #msg.html = "<b>testing</b>"
    #mail.send(msg)
    flash("Fonctionalité indisponible", "danger")
    return redirect(url_for('contact'))

@app.route("/logout.html", methods=["GET"])
@login_required
def logout():
    """Logout the current user."""
    user = current_user
    user.authenticated = False
    db.session.add(user)
    db.session.commit()
    logout_user()
    return render_template("index.html")

@app.route('/login.html', methods=['POST'])
def login():
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        user = User.query.get(form.username.data)
        if user and check_password_hash(user.password, form.password.data):
            user.authenticated = True
            db.session.add(user)
            db.session.commit()
            login_user(user, remember=True)
            return redirect(url_for("member"))
    return render_template('login.html', form=form)

@app.route('/member.html')
@login_required
def member(): return render_template("member.html")

@app.route('/contact.html')
def contact(): return render_template('contact.html')

login_manager.unauthorized_handler(login)

if __name__ == "__main__":
    app.run(host='0.0.0.0')
