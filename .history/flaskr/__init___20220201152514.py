import os

from flask import Flask

def create_app(test_config=None):
    """
    create_app is the application factory function. 
    """
    
    # create and configure the app
    # __name__ is the name of the current python moduel used to setup paths
    # instance_relative_config tells the app the files are within the working directory
    # can hold local data that shouldnt be pushed to git
    app = Flask(__name__, instance_relative_config=True)
    
    #used to set default configurationb in this case secret key and database path
    app.config.from_mapping(
        ##change to random hash when putting into prod
        SECRET_KEY='dev',
        ##change this at somepoint to point to a docker container
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        # use this to create a real secret
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        #ensures that app.instance_path exists flask doesnt create
        #the dir needs to exist for the database.
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # a simple page that says hello
    # creates the connection between flask and the website
    @app.route('/hello')
    def hello():
        return 'Hello, World!'

    #registers the db in the factory to be initialised in
    #the app
    from . import db
    db.init_app(app)
    
    #registers the auth blueprint in the factory to be init
    #in the app
    from . import auth
    app.register_blueprint(auth.bp)
        
    from . import blog
    app.register_blueprint(blog.bp)
    app.add_url_rule('/', endpoint='index')
    
    return app
