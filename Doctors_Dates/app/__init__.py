from flask import Flask
import os
from pymongo import MongoClient
from .routes import main

def create_app():
    
    app = Flask(__name__)
    app.secret_key = "lsknksdjcjks@@#34"

    # MongoDB connection setup
    # mongo_host = os.getenv('MONGO_HOST', 'localhost')
    # mongo_port = int(os.getenv('MONGO_PORT', 27017))
    # client = MongoClient(f'mongodb://{mongo_host}:{mongo_port}/')
    # db = client['HospitalDB']  # Replace with your MongoDB database name
    # settings_collection = db['Patients']  # Collection to store settings

    # # Retrieve or set the secret key
    # secret_key_document = settings_collection.find_one({'key_name': 'flask_secret_key'})
    # if not secret_key_document:
    #     secret_key = os.getenv('FLASK_SECRET_KEY', 'default_secret_key')  # Use env var or default
    #     settings_collection.insert_one({'key_name': 'flask_secret_key', 'value': secret_key})
    # else:
    #     secret_key = secret_key_document['value']

    # # Set the secret key for Flask sessions
    # app.secret_key = secret_key


    # Register blueprints, configure app, etc.
    
    app.register_blueprint(main)

    return app
    

