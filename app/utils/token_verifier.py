import jwt
import time
import logging
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from base64 import urlsafe_b64decode
from functools import lru_cache
from jwt.exceptions import InvalidTokenError
from app.config import Config

OKTA_DOMAIN = Config.OKTA_DOMAIN
OKTA_SERVER = Config.OKTA_SERVER
JWKS_URL = f'https://{OKTA_DOMAIN}/oauth2/{OKTA_SERVER}/v1/keys'
EXPECTED_AUDIENCE = Config.OKTA_AUDIENCE

logging.basicConfig(
    level = logging.DEBUG,
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers = [ logging.StreamHandler() ]
)

logger = logging.getLogger("SSO-Token-Verifier")

def ttl_lru_cache(seconds_to_live: int, maxsize: int):
    def wrapper(func):
        @lru_cache(maxsize)
        def inner(__ttl, *args, **kwargs):
            return func(*args, **kwargs)
        return lambda *args, **kwargs: inner(time.time() // seconds_to_live, *args, **kwargs)
    return wrapper

@ttl_lru_cache(seconds_to_live=100, maxsize=1)
def get_public_key_from_jwks(kid):
    response = requests.get(JWKS_URL)
    jwks = response.json()

    for key in jwks['keys']:
        if key['kid'] == kid:
            public_key_data = {
                'kty': key['kty'],
                'n': key['n'],
                'e': key['e']
            }
            return public_key_data
    return None

def construct_rsa_key(n, e):
    n = int.from_bytes(urlsafe_b64decode(n + '=='), 'big')
    e = int.from_bytes(urlsafe_b64decode(e + '=='), 'big')
    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def verify_token(token):
    try:
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header['kid']
        public_key_data = get_public_key_from_jwks(kid)
        
        if not public_key_data:
            raise ValueError('Public key not found for the given kid')
        
        public_key_pem = construct_rsa_key(public_key_data['n'], public_key_data['e'])
        decoded_token = jwt.decode(
            token,
            public_key_pem,
            algorithms=['RS256'],
            audience=EXPECTED_AUDIENCE,
            issuer=f'https://{OKTA_DOMAIN}/oauth2/{OKTA_SERVER}',
            options={'verify_signature': True}
        )
        return 200

    except InvalidTokenError as e:
        logging.debug(f'Invalid Token Error: {e}')
        return 401
    except Exception as e:
        logging.debug(f'Generic Token Error: {e}')
        return 401