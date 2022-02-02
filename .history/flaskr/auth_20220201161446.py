import functools

from flask import Blueprint
from flask import flash
from flask import g 
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

from flaskr.db import get_db

"""
This creates a Blueprint named 'auth'. Like the application object, 
the blueprint needs to know where it’s defined, so __name__ is 
passed as the second argument. The url_prefix will be prepended 
to all the URLs associated with the blueprint.

Import and register the blueprint from the factory using 
app.register_blueprint(). Place the new code at the end 
of the factory function before returning the app.
"""

bp = Blueprint('auth', __name__, url_prefix='/auth')


"""
@bp.route associates the URL /register with the register 
view function. When Flask receives a request to /auth/register, 
it will call the register view and use the return value as 
the response.
"""
@bp.route('/register', methods=('GET', 'POST'))
def register():
    #If the user submitted the form, request.method will be 'POST'. 
    #In this case, start validating the input.
    if request.method == 'POST':
        #request.form is a special type of dict mapping submitted 
        #form keys and values. 
        #The user will input their username and password.
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        #Validate that username and password are not empty.
        #If validation succeeds, insert the new user data into the database.
        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            try:
                """
                db.execute takes a SQL query with ? placeholders for any user 
                input, and a tuple of values to replace the placeholders with. 
                The database library will take care of escaping the values so 
                you are not vulnerable to a SQL injection attack.
                """
                """
                For security, passwords should never be stored in the database 
                directly. Instead, generate_password_hash() is used to securely 
                hash the password, and that hash is stored. Since this query 
                modifies data, db.commit() needs to be called afterwards to 
                save the changes.
                """
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
                
                """
                An sqlite3.IntegrityError will occur if the username already exists,
                which should be shown to the user as another validation error.
                """
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                """
                After storing the user, they are redirected to the login page. 
                url_for() generates the URL for the login view based on its name. 
                This is preferable to writing the URL directly as it allows you 
                to change the URL later without changing all code that links to it. redirect() generates a redirect response to the generated URL.
                """
                return redirect(url_for("auth.login"))

        #If validation fails, the error is shown to the user. 
        #flash() stores messages 
        #that can be retrieved when rendering the template.
        flash(error)

    #renders the template for the user.
    return render_template('auth/register.html')


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        
        #fetchone() returns one row from the query. 
        #If the query returned no results, it returns None.
        #Later, fetchall() will be used, which returns a 
        #list of all results.
        user = db.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()
        
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view