import pytest
from flask import url_for
from flask_login import current_user
from bson.objectid import ObjectId

@pytest.fixture
def user_data():
    return {
        '_id': ObjectId(),
        'email': 'test@example.com',
        'password': 'hashed_password',
        'setup_complete': False
    }

def test_wizard_access_unauthenticated(client):
    response = client.get('/wizard')
    assert response.status_code == 302
    assert 'login' in response.location

def test_wizard_access_authenticated(client, app, user_data):
    with app.app_context():
        app.db.users.insert_one(user_data)
        with client.session_transaction() as sess:
            sess['user_id'] = str(user_data['_id'])
        
        response = client.get('/wizard')
        assert response.status_code == 200
        assert b'Complete Your Business Setup' in response.data

def test_wizard_form_submission(client, app, user_data):
    with app.app_context():
        app.db.users.insert_one(user_data)
        with client.session_transaction() as sess:
            sess['user_id'] = str(user_data['_id'])
        
        form_data = {
            'business_name': 'Test Business',
            'address': '123 Test Street, City',
            'industry': 'retail'
        }
        
        response = client.post('/wizard', data=form_data, follow_redirects=True)
        assert response.status_code == 200
        assert b'Business setup completed successfully!' in response.data
        
        updated_user = app.db.users.find_one({'_id': user_data['_id']})
        assert updated_user['setup_complete'] == True
        assert updated_user['business_details']['name'] == 'Test Business'

def test_wizard_redirect_completed(client, app, user_data):
    user_data['setup_complete'] = True
    with app.app_context():
        app.db.users.insert_one(user_data)
        with client.session_transaction() as sess:
            sess['user_id'] = str(user_data['_id'])
        
        response = client.get('/wizard', follow_redirects=True)
        assert response.status_code == 200
        assert b'general_dashboard' in response.request.url