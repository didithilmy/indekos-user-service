import os
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask import request, redirect
from Crypto.PublicKey import RSA
import base64
from uuid import uuid4
import jwt
from datetime import timezone, datetime
import requests
import urllib.parse as urlparse
from urllib.parse import urlencode

app = Flask(__name__, static_folder='static', static_url_path='')
app.config['SQLALCHEMY_DATABASE_URI'] = str(os.getenv("DATABASE_URI", 'sqlite:///test.db'))
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

active_jwt_key = ('', '', '')

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(80), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=False, nullable=False)
    isAdmin = db.Column(db.Boolean, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.email

class KeyPair(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    active = db.Column(db.Boolean, nullable=False)
    uuid = db.Column(db.String(80), unique=True, nullable=False)
    private_key = db.Column(db.String(2048), unique=False, nullable=False)
    public_key = db.Column(db.String(2048), unique=False, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.email

@app.route("/login", methods=["GET"])
def login():
    redirect_uri = request.args.get('redirect_uri')

    if not redirect_uri:
        return "Redirect URI not specified"

    return render_template("login.html", redirect_uri=redirect_uri)

@app.route("/login", methods=["POST"])
def login_post():
    email = request.form['email']
    password = request.form['password']
    redirect_uri = request.form['redirect_uri']

    if not redirect_uri:
        return "Redirect URI not specified"

    user = User.query.filter_by(email=email).first()

    if (user != None):
        hash = user.password
        valid = bcrypt.check_password_hash(hash, password)
        if (valid):
            token = create_jwt(user)
            url_parts = list(urlparse.urlparse(redirect_uri))
            query = dict(urlparse.parse_qsl(url_parts[4]))
            query.update({'token': token})

            url_parts[4] = urlencode(query)
            redirect_to = urlparse.urlunparse(url_parts)

            return redirect(redirect_to, code=302)
        else:
            return render_template("login.html", error = "Invalid email and/or password", redirect_uri=redirect_uri)
    else:
        return render_template("login.html", error="Invalid email and/or password", redirect_uri=redirect_uri)

def create_jwt(user):
    global active_jwt_key
    (kid, public_key, private_key) = active_jwt_key

    key = RSA.importKey(base64.b64decode(private_key))
    iat = int(datetime.now(tz=timezone.utc).timestamp())

    payload = {
        'name': user.name,
        'email': user.email,
        'sub': user.id,
        'iat': iat,
        'exp': iat + 3600,
        'is_admin': user.isAdmin
    }

    return jwt.encode(payload, key.exportKey("PEM"), algorithm='RS256', headers={'kid': kid})


@app.route("/register", methods=["GET"])
def register():
    redirect_uri = request.args.get('redirect_uri')
    return render_template("register.html", redirect_uri=redirect_uri)

@app.route("/register", methods=["POST"])
def register_post():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']
    redirect_uri = request.form['redirect_uri']

    hashedPassword = bcrypt.generate_password_hash(password)

    user = User(name=name, email=email, password=hashedPassword, isAdmin=False)

    try:
        db.session.add(user)
        db.session.commit()

        if not redirect_uri:
            return redirect('/login')
        else:
            return redirect('/login?redirect_uri=' + urlencode(redirect_uri))
    except Exception as error:
        print('Error', error)
        return render_template("register.html", redirect_uri=redirect_uri, error="Email already registered")

def generate_key():
    key = RSA.generate(2048)
    uuid = str(uuid4())
    public_key = base64.b64encode(key.publickey().exportKey('DER')).decode('utf-8')
    private_key = base64.b64encode(key.exportKey('DER')).decode('utf-8')
    keyPair = KeyPair(uuid=uuid, private_key=private_key, public_key=public_key, active=True)
    db.session.add(keyPair)
    db.session.commit()
    print("Key pair with uuid: " + uuid + " is generated", public_key)

    publicKeyRegistryUrl = str(os.getenv("PUBLIC_KEY_REGISTRY_URL", "https://publickey.api.indekos.xyz"))
    r = requests.post(publicKeyRegistryUrl + "/v1/keys/" + uuid, json={'publicKey': public_key})
    print(r.json())

    return (uuid, public_key, private_key)

def get_active_key():
    global active_jwt_key

    active_keypair  = KeyPair.query.filter_by(active=True).first()
    if (active_keypair == None):
        print("Key not exists, generating new one...")
        (uuid, public_key, private_key) = generate_key()
        active_jwt_key = (uuid, public_key, private_key)
    else:
        active_jwt_key = (active_keypair.uuid, active_keypair.public_key, active_keypair.private_key)

def init():
    db.create_all()
    get_active_key()


if __name__ == '__main__':
    init()
    app.run(debug=True, host='0.0.0.0')