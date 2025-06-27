from pymongo import MongoClient

def run_migration():
    client = MongoClient('mongodb://localhost:27017/')
    db = client['your_database']
    users_collection = db['users']
    
    # Add setup_complete field to existing users
    result = users_collection.update_many(
        {'setup_complete': {'$exists': False}},
        {'$set': {'setup_complete': False}}
    )
    
    print(f"Migration completed. Updated {result.modified_count} user documents.")

if __name__ == '__main__':
    run_migration()