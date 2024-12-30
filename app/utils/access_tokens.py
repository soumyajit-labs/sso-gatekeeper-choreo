import base64
import requests
from app.config import Config

TOKEN_URL = Config.TOKEN_URL
CLIENT_ID = Config.CLIENT_ID
CLIENT_SECRET = Config.CLIENT_SECRET

def base64_encoder(string):
    return str(base64.b64encode(bytes(string, 'ascii')), 'ascii')

def get_oauth_tokens(saml_code):    
    response = requests.post(
        TOKEN_URL,
        data={
            'grant_type': 'urn:ietf:params:oauth:grant-type:saml2-bearer',
            'assertion': saml_code.decode('utf-8'),
            'scope': 'openid profile email offline_access',
        },
        headers={
            'Authorization': 'Basic ' + base64_encoder(CLIENT_ID + ':' + CLIENT_SECRET),
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        return None
    
def get_new_oauth_tokens(refresh_token):
    response = requests.post(
        TOKEN_URL,
        headers = { 'Content-Type': 'application/x-www-form-urlencoded' }, 
        data = {
            'grant_type': 'refresh_token',
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'refresh_token': refresh_token,
        }
    )
    
    if response.status_code == 200:
        return response.json()
    else:
        None