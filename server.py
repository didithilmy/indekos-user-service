import os
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask import request
from Crypto.PublicKey import RSA
import base64
from uuid import uuid4
import jwt
from datetime import timezone, datetime
import requests

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
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login_post():
    email = request.form['email']
    password = request.form['password']
    user = User.query.filter_by(email=email).first()

    if (user != None):
        hash = user.password
        valid = bcrypt.check_password_hash(hash, password)
        if (valid):
            return create_jwt(user)
        else:
            return render_template("login.html", error = "Invalid email and/or password")
    else:
        return render_template("login.html", error="Invalid email and/or password")

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
        'exp': iat + 3600
    }

    return jwt.encode(payload, key.exportKey("PEM"), algorithm='RS256', headers={'kid': kid})


@app.route("/register", methods=["GET"])
def register():
    return render_template("register.html")

@app.route("/register", methods=["POST"])
def register_post():
    name = request.form['name']
    email = request.form['email']
    password = request.form['password']

    hashedPassword = bcrypt.generate_password_hash(password)

    user = User(name=name, email=email, password=hashedPassword)
    db.session.add(user)
    db.session.commit()
    return "OK"

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

init()