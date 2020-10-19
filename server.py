from flask import Flask, render_template, redirect, url_for, flash, request, g, send_from_directory
from flask_mail import Mail, Message
from flask_login import LoginManager, login_required, login_user, current_user, logout_user
from wtforms import Form, StringField, validators, SubmitField, PasswordField, MultipleFileField, TextAreaField
from wtforms.fields.html5 import EmailField
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt, check_password_hash
from werkzeug.utils import secure_filename
from os import path, makedirs, urandom
from datetime import datetime
from smtplib import SMTP
from email.message import EmailMessage

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
    email = db.Column(db.String, nullable=False)
    authenticated = db.Column(db.Boolean, default=False)
    admin = db.Column(db.Boolean, default=False)

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

class ContactForm(Form):
    name = StringField(validators=[validators.required()], render_kw={'placeholder':'Nom', 'class': 'form-control', 'style': 'background-color:rgba(255,255,255,0.5);'})
    subject = StringField(validators=[validators.required()], render_kw={'placeholder':'Sujet', 'class': 'form-control', 'style': 'background-color:rgba(255,255,255,0.5);'})
    email = EmailField(validators=[validators.required()], render_kw={'placeholder':'Email', 'class': 'form-control', 'style': 'background-color:rgba(255,255,255,0.5);'})
    message = TextAreaField(validators=[validators.required()], render_kw={'placeholder':'Message', 'class': 'form-control', 'style': 'background-color:rgba(242,242,242,0.5);', 'rows': '8'})
    submit = SubmitField(render_kw={'class': 'btn-light my-3 col-2', 'value': 'Envoyer', 'style': 'background-color:rgba(242,242,242,0.5)'})

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

def duplicate_doctor_name_check(form, field):
    doctors = User.query.filter_by(email=field.data)
    return doctors == None or doctors.first() == None

class RegisterForm(Form):
    email = EmailField(validators=[validators.required(), duplicate_doctor_name_check],
                       render_kw={'placeholder':'Email client'})
    submit = SubmitField(render_kw={'value': 'Envoyer email d\'enregistrement'})

class UploadFileForm(Form):
    files = MultipleFileField('Fichier', render_kw={'onchange':'document.getElementById("output").src = window.URL.createObjectURL(this.files[0]);document.getElementById("output").style.visibility="visible";form.submit()'})
    submit = SubmitField(render_kw={'value': 'Rajouter le(s) fichier(s) dans le dossier'})

@login_manager.user_loader
def load_user(user_id): return User.query.get(user_id)

@app.route('/')
def default(): return render_template('index.html')

@app.route('/index.html')
def index(): return render_template('index.html')

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
            if user.admin: return redirect(url_for("admin"))
            return redirect(url_for("member"))
    return render_template('/login.html', form=form)

@app.route('/admin.html', methods=['GET', 'POST'])
@login_required
def admin():
    registration_form = RegisterForm(request.form)
    if request.method == 'POST' and registration_form.validate():
        if not current_user.admin:
            flash('Vous n\'avez pas le droit d\'enregistrer un client', 'danger')
            return redirect(url_for('index'))
        flash('Email envoyé', 'success')
        send_mail(registration_form.email.data, "Email d'enregistrement au service en ligne d'Amel Ben Brahim",
                  "Fonctionalité indisponible")
    if not current_user.admin: return redirect(url_for('member'))
    files = PatientFiles.query.all()
    return render_template('admin.html', files = files, registration_form = registration_form)

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

def send_mail(receiver, subject, body):
    app.logger.info("Instantiating SMTP server")
    with SMTP('smtp.gmail.com:587', timeout=5) as server:
        app.logger.info("EHLO")
        server.ehlo()
        app.logger.info("Start TLS")
        server.starttls()
        app.logger.info("EHLO")
        server.ehlo()
        app.logger.info("Logging to SMTP server")
        server.login('brahimalekhine@gmail.com', 'alekhinebrahim')
        email = EmailMessage()
        email.set_content(body)
        email['From'] = 'noreply@ortonabeul.tn'
        email['To'] = receiver
        email['Subject'] = subject
        message = f"Subject: {subject}\n\n{body}"
        app.logger.info("Sending email")
        server.send_message(email)

@app.route('/contact.html', methods=['GET', 'POST'])
def contact():
    form = ContactForm(request.form)
    if request.method == 'POST' and form.validate():
        try:
            message = 'Nom: %s\r\nEmail: %s\r\n %s' % (form.name.data, form.email.data, form.message.data)
            send_mail("brahim.pro@protonmail.com", request.form['subject'], message)
            flash("Message envoyé", "success")
        except Exception as e:
            app.logger.error(str(e))
            flash("Une erreur technique est survenue, veuillez contacter le cabinet par téléphone", "danger")
    return render_template('contact.html', form=form)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/valider/<int:id>')
@login_required
def valider(id):
    patient_files = PatientFiles.query.get(id)
    if patient_files.doctor_name != current_user.name and not current_user.admin:
        flash('Vous n\'avez pas le droit de modifier ce fichier', 'danger')
        return redirect(url_for("index"))
    if patient_files.state == "Nouveau": patient_files.state = "Ouvert"
    elif patient_files.state == "Ouvert": patient_files.state = "Valide"
    elif patient_files.state == "Valide": patient_files.state = "En attente de l'avance"
    elif patient_files.state == "En attente de l'avance": patient_files.state = "En attente STL"
    elif patient_files.state == "En attente STL": patient_files.state = "STL valide"
    db.session.commit()
    return redirect('/file/' + patient_files.name);

@app.route('/file/<patient_file_name>', methods=['GET', 'POST'])
@login_required
def patient_file(patient_file_name):
    if not current_user.admin:
        patient_files = PatientFiles.query.filter_by(name=patient_file_name, doctor_name=current_user.name)
    else:
        patient_files = PatientFiles.query.filter_by(name=patient_file_name)
    if patient_files == None or patient_files.first() == None:
        flash('Dossier inconnu', 'danger')
        return redirect(request.url)
    patient_files = patient_files.first()
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
            new_dir = path.join(app.config['UPLOAD_FOLDER'], patient_files.doctor_name)
            if not path.exists(new_dir): makedirs(new_dir, exist_ok=True)
            new_path = path.join(new_dir, filename)
            file.save(new_path)
            db_file = File(name=file.filename, path=new_path, patient_files=patient_files.id)
            db.session.add(db_file)
            db.session.commit()
        return redirect(request.url)
    if not current_user.admin:
        files = [ path.basename(file.path) for file in File.query.filter_by(patient_files=patient_files.id) ]
    else:
        files = [ path.basename(file.path) for file in File.query.all() ]
    return render_template("/file.html", files=files, form=form,
                           state=patient_files.state, id=patient_files.id)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(path.join(app.config['UPLOAD_FOLDER'], current_user.name), filename)
login_manager.unauthorized_handler(login)

if __name__ == "__main__":
    app.run(host='0.0.0.0')
