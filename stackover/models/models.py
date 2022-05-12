from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from dataclasses import dataclass

db = SQLAlchemy()


@dataclass
class User(db.Model):  
   __tablename__ = 'users'
   id = db.Column(db.Integer, primary_key=True)
   username = db.Column(db.String(80), unique=True, nullable=False)
   email = db.Column(db.String(120), unique=True, nullable=False)
   password = db.Column(db.Text(), nullable=False)
   created_at = db.Column(db.DateTime, default=datetime.now())
   


   def __repr__(self):
        return "<User %r>" % self.email

 

  
    
@dataclass
class Question(db.Model):
    id: int
    title:str
    body:str
    user_id:int
    answers: list
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String,unique=True,nullable=False)
    body = db.Column(db.Text,unique=True, nullable=False)
    answers = db.relationship('Answer', backref="question")
    user_id = db.Column(db.Integer, db.ForeignKey('users.id',ondelete='CASCADE'))
    posted_date = db.Column(db.DateTime, default=datetime.now())
    

    
    def __repr__(self):
        return "<Question %r>" % self.title
@dataclass
class Answer(db.Model):
    id: int
    body:str
    user_id:int
    __tablename__ = 'answers'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id',ondelete='CASCADE'))
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id',ondelete='CASCADE'))
    posted_date = db.Column(db.DateTime, default=datetime.now())
    
      
    def __repr__(self):
        return "<Answers %r>" % self.id

    
    



 