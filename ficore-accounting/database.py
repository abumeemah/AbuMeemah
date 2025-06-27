from pymongo import MongoClient
import os
import logging

logger = logging.getLogger(__name__)

def get_db(mongo_uri=None):
    """
    Connects to the MongoDB database specified by mongo_uri.
    Returns the database object.
    """
    try:
        mongo_uri = mongo_uri or os.getenv('MONGO_URI', 'mongodb://localhost:27017/minirecords')
        client = MongoClient(mongo_uri, uuidRepresentation='standard')
        db_name = mongo_uri.split('/')[-1].split('?')[0] or 'minirecords'
        db = client[db_name]
        # Test connection
        db.command('ping')
        logger.info(f"Successfully connected to MongoDB database: {db_name}")
        return db
    except Exception as e:
        logger.error(f"Error connecting to database: {str(e)}")
        raise
