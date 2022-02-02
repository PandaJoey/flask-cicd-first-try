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

db.execute takes a SQL query with ? placeholders for any user 
input, and a tuple of values to replace the placeholders with. 
The database library will take care of escaping the values so 
you are not vulnerable to a SQL injection attack.
            
For security, passwords should never be stored in the database 
directly. Instead, generate_password_hash() is used to securely 
hash the password, and that hash is stored. Since this query 
modifies data, db.commit() needs to be called afterwards to 
save the changes.
                
An sqlite3.IntegrityError will occur if the username already exists,
which should be shown to the user as another validation error.

After storing the user, they are redirected to the login page. 
url_for() generates the URL for the login view based on its name. 
This is preferable to writing the URL directly as it allows you 
to change the URL later without changing all code that links to it. redirect() generates a redirect response to the generated URL.


"""
@bp.route('/register', methods=('GET', 'POST'))
def register():
    #If the user submitted the form, request.method will be 'POST'. 
    #In this case, start validating the input.
    if request.method == 'POST':
        #request.form is a special type of dict mapping submitted form keys and values. 
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
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()

            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))

        #If validation fails, the error is shown to the user. flash() stores messages 
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
        
        """
        fetchone() returns one row from the query. 
        If the query returned no results, it returns None.
        Later, fetchall() will be used, which returns a 
        list of all results.
        """
        user = db.execute('SELECT * FROM user WHERE username = ?', (username,)).fetchone()

        if user is None:
            error = 'Incorrect username.'
        #check_password_hash() hashes the submitted password in the same way as the 
        #stored hash and securely compares them. If they match, the password is valid.
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        """
        session is a dict that stores data across requests. 
        When validation succeeds, the users id is stored in a new session. 
        The data is stored in a cookie that is sent to the browser, 
        and the browser then sends it back with subsequent requests. 
        Flask securely signs the data so that it cant be tampered with.
        """
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')


"""
bp.before_app_request() registers a function that runs 
before the view function, no matter what URL is requested. 
load_logged_in_user checks if a user id is stored in the 
session and gets that users data from the database, 
storing it on g.user, which lasts for the length of the request. 
If there is no user id, or if the id doesn’t exist, 
g.user will be None.
"""
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
 
        
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


"""
The url_for() function generates the URL to a view based on 
a name and arguments. The name associated with a view 
is also called the endpoint, and by default its the
same as the name of the view function.

For example, the hello() view that was added to the app 
factory earlier in the tutorial has the name 'hello' 
and can be linked to with url_for('hello'). If it took 
an argument, which youll see later, it would be linked 
to using url_for('hello', who='World').

When using a blueprint, the name of the blueprint is 
prepended to the name of the function, so the endpoint 
for the login function you wrote above is 'auth.login'
because you added it to the 'auth' blueprint.
"""

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view