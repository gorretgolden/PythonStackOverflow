import re
from flask import  jsonify, request, Blueprint
from werkzeug.security import check_password_hash,generate_password_hash
from flask_jwt_extended import  create_access_token
from stackover.models.models import User
from stackover.models.models import db


auth = Blueprint('auth', __name__, url_prefix='/auth')



#signup endpoint
@auth.route('/signup', methods= ['POST','GET'])
def register():
  
  if request.method == "POST":
        
      username = request.json['username']
      email = request.json['email']
      password = request.json['password']

      
      if not email and not username and not password:
              return jsonify({'error':"All fields are required"})
      
      if len(password) < 6:
            return jsonify({'error': "Your password is too short"})

      if len(username) < 3:
        return jsonify({'error': "Your username is too short"})

    

      if User.query.filter_by(email=email).first() is not None:
        return jsonify({'error': "The email is already taken"})

      if User.query.filter_by(username=username).first() is not None:
        return jsonify({'error': "The username is taken"})
       
   
      hashed_password = generate_password_hash(password,method="sha256")
      new_user = User(username=username, password=hashed_password, email=email)  

      db.session.add(new_user)
      db.session.commit()
 
        
      return jsonify({'username':username,'email':email})
  return jsonify({'error':'You provided wrong credentials try again'}) 



@auth.route('/login', methods= ['POST'])

def login():
        
   
         if request.method == 'POST':
           email = request.json["email"]
           password = request.json['password']
        
          #empty fields
      
           if not email:
                 
                return jsonify({'error': 'Please provide your email '})
          
         
           user = User.query.filter_by(email=email).first()
           if user:
            password_correct = check_password_hash(user.password, password)

            if password_correct:
            
              token = create_access_token(identity=user.id)

              return jsonify({
                'user': {
                    
                    'token': token,
              
                    'email': user.email
                 }

                })
            
 
                
           return jsonify({'error': 'Wrong credentials'})

      
          
        







