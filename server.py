from flask import Flask, render_template, redirect, url_for, flash, request, g, send_from_directory
from flask_mail import Mail, Message
from flask_login import LoginManager, login_required, login_user, current_user, logout_user
from wtforms import Form, StringField, validators, SubmitField, PasswordField, MultipleFileField
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash
from werkzeug.utils import secure_filename
from os import path, makedirs, urandom
from datetime import datetime

app = Flask(__name__)
app.secret_key = urandom(16)
mail = Mail()
mail.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./database.sqlite'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
ALLOWED_EXTENSIONS = { 'png', 'jpg', 'jpeg', 'gif' }
app.config['UPLOAD_FOLDER'] = path.dirname(path.realpath(__file__)) + '/uploads'

class User(db.Model):
    """A user capable of viewing reports.

    :param str name: name address of user
    :param str password: encrypted password for the user

    """
    __tablename__ = 'user'

    name = db.Column(db.String, primary_key=True)
    password = db.Column(db.String, nullable=False)
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

class PatientFiles(db.Model):
    """A treatment file

    :param str name: File name
    :param str doctor_name: Doctor that created files

    """

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    doctor_name = db.Column(db.String, db.ForeignKey('user.name'))
    state = db.Column(db.String, default="Nouveau")

    def __repr__(self):
        return '<PatientFiles %r / %r>' % (self.name, self.doctor_name)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    path = db.Column(db.String)
    patient_files = db.Column(db.String, db.ForeignKey('patient_files.id'))

    def __repr__(self):
        return '<File Original name: %r / Path: %r>' % (self.name, self.path)

class LoginForm(Form):
    username = StringField(validators=[validators.required()], render_kw={'placeholder':'Nom'})
    password = PasswordField(validators=[validators.required()], render_kw={'placeholder':'Mot de passe'})
    submit = SubmitField(render_kw={'value': 'Connexion'})

def duplicate_name_check(form, field):
    PatientFiles.query.filter_by(name=field.data)
    return PatientFiles != None

class NewFileForm(Form):
    name = StringField(validators=[validators.required(), duplicate_name_check], render_kw={'placeholder':'Nom du dossier'})
    submit = SubmitField(render_kw={'value': 'Nouveau dossier'})

class UploadFileForm(Form):
    files = MultipleFileField('Fichier', render_kw={'onchange':'document.getElementById("output").src = window.URL.createObjectURL(this.files[0]);document.getElementById("output").style.visibility="visible";'})
    submit = SubmitField(render_kw={'value': 'Télécharger un fichier'})

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
    return render_template("/index.html")

@app.before_request
def load_logged_in_user():
    g.current_user = current_user

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
    return render_template('/login.html', form=form)

@app.route('/member.html', methods=['GET', 'POST'])
@login_required
def member():
    form = NewFileForm(request.form)
    if request.method == "POST" and form.validate():
        file = PatientFiles(name=form.name.data, doctor_name=current_user.name)
        db.session.add(file)
        db.session.commit()
    files = PatientFiles.query.filter_by(doctor_name=current_user.name)
    return render_template("/member.html", form=form, files=files)

@app.route('/contact.html')
def contact(): return render_template('contact.html')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/file/<patient_file_name>', methods=['GET', 'POST'])
@login_required
def patient_file(patient_file_name):
    patients_file = PatientFiles(name=patient_file_name, doctor_name=current_user.name)
    if patients_file == None:
        flash('Dossier inconnu', 'danger')
        return redirect(requst.url)
    form = UploadFileForm(request.form)
    if request.method == 'POST' and form.validate():
        # check if the post request has the file part
        files = request.files.getlist(form.files.name)
        if len(files) == 0:
            flash('Aucun Téléchargé', 'warning')
            return redirect(request.url)
        for file in files:
            if file == None or file.filename == '':
                flash('Aucun fichier', 'warning')
                continue
            if not allowed_file(file.filename):
                flash('Extension non authorisée', 'warning');
            filename = secure_filename(file.filename)
            extension = filename[-4:]
            base_name = filename[:-4]
            filename = base_name + datetime.now().isoformat(timespec='microseconds') + extension
            new_dir = path.join(app.config['UPLOAD_FOLDER'], current_user.name)
            if not path.exists(new_dir): makedirs(new_dir, exist_ok=True)
            new_path = path.join(new_dir, filename)
            file.save(new_path)
            db_file = File(name=file.filename, path=new_path, patient_files=patients_file.id)
            db.session.add(db_file)
            db.session.commit()
        return redirect(request.url)
    files = File.query.filter_by(patient_files=patients_file.id)
    return render_template("/file.html", files=[path.basename(file.path) for file in files ], form=form)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(path.join(app.config['UPLOAD_FOLDER'], current_user.name), filename)
login_manager.unauthorized_handler(login)

if __name__ == "__main__":
    app.run(host='0.0.0.0')
