import os

class Config:
    #SQLALCHEMY_DATABASE_URI = 'postgresql://Postgres:mysecretpassword@localhost/authdb'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'postgresql://Postgres:mysecretpassword@authdb/authdb'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'your_secret_key'
