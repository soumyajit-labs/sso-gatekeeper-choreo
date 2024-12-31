import os
from dotenv import load_dotenv
load_dotenv()

class Config:
    DEBUG_FLAG = os.getenv('DEBUG_FLAG')
    TOKEN_URL = os.getenv('TOKEN_URL')
    CLIENT_ID = os.getenv('CLIENT_ID')
    CLIENT_SECRET = os.getenv('CLIENT_SECRET')
    APP_KEY = os.getenv('APP_KEY')
    OKTA_DOMAIN = os.getenv('OKTA_DOMAIN')
    FE_DOMAIN = os.getenv('FE_DOMAIN')
    FE_LANDING_URL = os.getenv('FE_LANDING_URL')
    REFRESH_IP_WHITELIST = os.getenv('REFRESH_IP_WHITELIST')