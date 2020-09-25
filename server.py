from flask import Flask, render_template
app = Flask(__name__)

# To be removed in  prod
# I use this in development to apply changes I do on the browser
# Otherwise only the cached file is shown
@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r
@app.route('/')
def default():
    return render_template('index.html')
@app.route('/index.html')
def index():
    return render_template('index.html')
@app.route('/contact.html')
def contact():
    return render_template('contact.html')

if __name__ == "__main__":
    app.run(host='0.0.0.0')