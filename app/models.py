from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash


db = SQLAlchemy()


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(45), nullable = False, unique = True)
    email = db.Column(db.String(100), nullable = False, unique = True)
    password = db.Column(db.String(45), nullable = False)
    apitoken = db.Column(db.String)

    def __init__(self, username, email, password, apitoken):
        self.username = username
        self.email = email
        self.password = generate_password_hash(password)
        self.apitoken = apitoken

    def saveToDB(self):
        db.session.add(self)
        db.session.commit()

# Must have this function to send data to React
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'apitoken': self.apitoken
        }

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    img_url = db.Column(db.String, nullable=False)
    details = db.Column(db.String(1000))
    price = db.Column(db.String(10), nullable=False)
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())
    cart = db.relationship('Cart', backref='info', lazy=True)

    def __init__(self, name, img_url, details, price):
        self.name = name
        self.img_url = img_url
        self.details = details
        self.price = price

    def saveToDB(self):
        db.session.add(self)
        db.session.commit()

    def deletefromDB(self):
        db.session.delete(self)
        db.session.commit()

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'img_url': self.img_url,
            'details': self.details,
            'price': self.price,
            'date_created': self.date_created 
        }




class Cart(db.Model):
    __tablename__ = 'cart'
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('item.id'), nullable=False)
    customer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def saveToDB(self):
        db.session.add(self)
        db.session.commit()

    def deletefromDB(self):
        db.session.delete(self)
        db.session.commit()

    def to_dict(self):
        return {
            'id': self.id,
            'item_id': self.item_id,
            'customer_id': self.customer_id
        }
