from flask import Flask, jsonify, request, Response
from flask_sqlalchemy import SQLAlchemy
import jwt
from jwt.exceptions import DecodeError, MissingRequiredClaimError, InvalidKeyError
import json
from base64 import b64decode
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SECRET_KEY_HMAC'] = 'secret'

with open('public.pem','r') as f:
    app.config['PUBLIC_KEY_RSA'] = f.read()


db = SQLAlchemy(app)

class User(db.Model):
    '''
    Using SQLAlchemy to generate a SQLite DB. This is a very minimal user table with username and password.
    The username:password combinations used in the default DB is "admin:admin123", "guest:guest123"
    '''
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(80), unique = True)
    password = db.Column(db.String(80), unique = True)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __repr__(self):
        return "<User {0}>".format(self.username)

def get_exp_date():
    exp_date = datetime.datetime.utcnow() + datetime.timedelta(minutes = 1)
    return exp_date



def verify_jwt(token):
    try:
        decoded = jwt.decode(token, app.config['SECRET_KEY_HMAC'], verify=True, issuer = 'we45', leeway=10, algorithms=['HS256'])
        print("JWT Token from API: {0}".format(decoded))
        return True
    except DecodeError:
        print("Error in decoding token")
        return False
    except MissingRequiredClaimError as e:
        print('Claim required is missing: {0}'.format(e))
        return False


def verify_rsa_jwt(token):
    try:
        decoded = jwt.decode(token, app.config['PUBLIC_KEY_RSA'])
        print("JWT Token from API: {0}".format(decoded))
        return True
    except DecodeError:
        print("Error in decoding Token")
        return False
    except InvalidKeyError as key:
        print(key)
        return False



def insecure_verify(token):
    decoded = jwt.decode(token, verify = False)
    print decoded
    return True

@app.route('/login', methods = ['POST'])
def login():
    '''
    You will need to authenticate to this URI first. You will need to pass a JSON body with a username and password key.
    If you enter a valid username and password, a JWT token is returned in the HTTP Response in the Authorization header.
    This token can be used for subsequent requests.
    '''
    try:
        content = request.json
        username = content['username']
        password = content['password']
        auth_user = User.query.filter_by(username = username, password = password).first()
        if auth_user:
            auth_token = jwt.encode({'user': username, 'exp': get_exp_date(), 'nbf': datetime.datetime.utcnow(), 'iss': 'we45', 'iat': datetime.datetime.utcnow()}, app.config['SECRET_KEY_HMAC'], algorithm='HS256')
            resp = Response(json.dumps({'Hello': username}))
            resp.headers['Authorization'] = "{0}".format(auth_token)
            resp.status_code = 200
            resp.mimetype = 'application/json'
            return resp
        else:
            return jsonify({'Error': 'No User here...'}),404
    except:
        return jsonify({'Error': 'Unable to recognize Input'}),404

@app.route('/auth', methods = ["GET"])
def protected_page():
    '''
    You will need to pass a valid JWT in the HTTP Authorization Header to get a valid response from this URL.
    The Token validates the signature, expiration and issuer claims. The
    '''
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'Error': 'No Token in Request'}), 404
    else:
        if not verify_jwt(token):
            return jsonify({'Error': 'Token cannot be validated'}),404
        else:
            return jsonify({'Hello': 'This is an authenicated response'}),200

@app.route('/insecure_auth', methods = ["GET"])
def insecure_page():
    '''
    This function does not verify the JWT. Hence, you can pass any JWT and it will accept it as valid.
    '''
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'Error': 'No Token in Request'}), 404
    else:
        if not insecure_verify(token):
            return jsonify({'Error': 'Token cannot be validated'}),404
        else:
            return jsonify({'Hello': 'This is an authenicated response'}),200

@app.route('/rsa_auth', methods = ["GET"])
def rsa_page():
    '''
       This function errors out when you throw a JWT that is signed with a public key. In this case, we are using the
       key from the public.pem file.
       '''
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'Error': 'No Token in Request'}), 404
    else:
        if not verify_rsa_jwt(token):
            return jsonify({'Error': 'Token cannot be validated'}),404
        else:
            return jsonify({'Hello': 'This is an authenicated response'}),200



if __name__ == '__main__':
    app.run(debug=True)