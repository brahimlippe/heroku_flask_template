from os import urandom
from flask import Flask, render_template, redirect, url_for, flash
app = Flask(__name__)

app.secret_key = urandom(16)
@app.route('/')
def default():
    return render_template('index.html')
@app.route('/index.html')
def index():
    return render_template('index.html')
@app.route('/email.html')
def email():
    flash("Message sent")
    return redirect(url_for('contact'))
@app.route('/contact.html')
def contact():
    return render_template('contact.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0')
