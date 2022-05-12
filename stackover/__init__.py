import os
from flask import Flask
from flask_jwt_extended import JWTManager
from stackover.models.models import db



#Application Factory Function
def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    

    if test_config is None:
  
       app.config.from_mapping(

        CORS_HEADERS= 'Content-Type',
        SQLALCHEMY_DATABASE_URI = "sqlite:///stackoverflow",
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        JWT_SECRET_KEY=os.environ.get('JWT_SECRET_KEY')
 
    )
    else:
      
        app.config.from_mapping(test_config)
   

   
    JWTManager(app)
    
    
   
    from stackover.questions.routes import questions
    from stackover.auth.routes import auth
 
    #registering blueprints    
  
    app.register_blueprint(questions)
    app.register_blueprint(auth)
    
    JWTManager(app)
   
    db.app = app
    db.init_app(app)
    db.create_all()
   
    return app

