from os import urandom
from flask import Flask, render_template, redirect, url_for, flash
from flask_mail import Mail, Message

mail = Mail()
app = Flask(__name__)
mail.init_app(app)

app.secret_key = urandom(16)
@app.route('/')
def default():
    return render_template('index.html')

@app.route('/index.html')
def index():
    return render_template('index.html')

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

@app.route('/contact.html')
def contact():
    return render_template('contact.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0')
