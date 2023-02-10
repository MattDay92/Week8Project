from flask import Blueprint, request
from flask_cors import cross_origin
from ..models import User
from werkzeug.security import check_password_hash
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth

api = Blueprint('api', __name__)


basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth()

@basic_auth.verify_password
def verifyPassword(username, password):
    user = User.query.filter_by(username=username).first()
    if user:
        if check_password_hash(user.password, password):
            return user

@token_auth.verify_token
def verifyToken(token):
    user = User.query.filter_by(apitoken=token).first()
    if user:
        return user


@api.route('/api/signup', methods=["POST"])
def signUpAPI():
    data = request.json

    username = data['username']
    email = data['email']
    password = data['password']

    user = User(username, email, password)

    user.saveToDB()

    return {
        'status': 'ok',
        'message': 'User successfully created!'
    }


@api.route('/api/login', methods=["POST"])
@basic_auth.login_required
def getToken():
    user = basic_auth.current_user()
    return {
        'status': 'ok',
        'user': user.to_dict()
    }

