import os
import string
import random

class Config(object):
    SECRET_KEY = os.urandom(16)
    SQLALCHEMY_DATABASE_URI = 'sqlite:///ctf.db'
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    ADMIN_PASSWORD = os.urandom(16).hex()

class ProductionConfig(Config):
    pass

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True