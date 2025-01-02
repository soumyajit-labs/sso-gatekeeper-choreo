import os
import socket
import logging
from flask import Flask, request, redirect, make_response, jsonify
from flask_cors import cross_origin
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.utils.access_tokens import get_oauth_tokens, get_new_oauth_tokens
from app.utils.saml_assert import encode_saml_assert, validate_saml_response, load_certificate
from app.utils.token_verifier import verify_token
from app.config import Config

app = Flask(__name__)
app.secret_key = Config.APP_KEY
serializer = URLSafeTimedSerializer(app.secret_key)

logging.basicConfig(
    level = logging.DEBUG,
    format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers = [ logging.StreamHandler() ]
)

logger = logging.getLogger("SSO-Gatekeeper")

OKTA_DOMAIN = Config.OKTA_DOMAIN

app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

talisman_csp = {
    'default-src': ["'self'"],
    'img-src': ["'self'", "https:"],
    'script-src': ["'self'"],
    'style-src': ["'self'", "https:"],
    'connect-src': ["'self'", f"https://{OKTA_DOMAIN}"],
}

# Set the 'force_https' as TRUE when deploying in Production
Talisman(app, force_https=False, frame_options='DENY',
         content_security_policy=talisman_csp)

@app.before_request
def before_request():
    if ((request.endpoint in ['sso','health','static', None]) or (request.path in ['/favicon.ico', '/'])):
        return
    try:
        csrf_token = request.cookies.get('csrf_token')
        logging.debug(f'CSRF Token: {csrf_token}')
        data = serializer.loads(csrf_token, max_age=3600)
        if csrf_token:
            return
    except (BadSignature, SignatureExpired):
        return 'Error: CSRF token is invalid or expired', 403

@app.route('/sso', methods=['POST'])
def sso():
    logging.info('Somebody just hit the /sso endpoint!')
    client_ip = request.remote_addr
    logging.debug(f'Client IP : {client_ip}')
    
    '''
    ** THIS PART IS FOR WHITELISTING WHICH I LATER REALISED IS NOT NEEDED **

        okta_ips = [addr[-1] for addr in socket.getaddrinfo(OKTA_DOMAIN, None)]
        logging.debug(f'Okta IPs : {okta_ips}')
        if (client_ip not in okta_ips):
            return 'Error: Unauthorized IP', 403
    '''
    
    saml_response = request.form.get('SAMLResponse')
    saml_code = encode_saml_assert(saml_response)
    if Config.ON_LOCAL == 'True':
        cert_path = 'assets/okta_cert_sha2.cert'
    else:
        cert_path = os.path.join(os.getcwd(), 'app', 'assets', 'okta_cert_sha2.cert')
    logging.debug(f'Certificate Path: {cert_path}')
    certificate = load_certificate(cert_path)
    try:
        if validate_saml_response(saml_response, certificate):
            '''
            ** Import this first if this is needed **
            from app.utils.user_attributes import extract_user_data_from_saml
            ** If we want to fetch user attributes & set as session variables **
                user_data = extract_user_data_from_saml(saml_response)
                session['email'] = user_data.get('email')
                session['first_name'] = user_data.get('firstName')
                session['last_name'] = user_data.get('lastName')
                session['username'] = user_data.get('username')
            '''
            tokens = get_oauth_tokens(saml_code)
            if tokens:
                # Setting up cookies - For prod, need to make the samesite attribute to 'Strict'
                csrf_token = serializer.dumps('csrf-token')
                logging.info(f'Routing to: {Config.FE_LANDING_URL}')
                response = make_response(redirect(Config.FE_LANDING_URL))
                response.set_cookie('csrf_token', csrf_token, httponly=True, secure=True, samesite='None')
                response.set_cookie('id_token', tokens['id_token'], httponly=True, secure=True, samesite='None')
                response.set_cookie('access_token', tokens['access_token'], httponly=True, secure=True, samesite='None')
                response.set_cookie('refresh_token', tokens['refresh_token'], httponly=True, secure=True, samesite='None')
                return response
            return 'Error: Unable to fetch tokens', 400
        else:
            return 'Error: SAML Response Validation Failed', 403
    except Exception as e:
        return f'Error: {str(e)}', 500

@app.route('/refresh', methods=['GET'])
@cross_origin(origins=[Config.FE_DOMAIN], supports_credentials=True)
def refresh():
    logging.info('Somebody just hit the /refresh endpoint!')
    client_ip = request.remote_addr
    logging.debug(f'Client IP : {client_ip}')
    white_listed_ips = (Config.REFRESH_IP_WHITELIST).split(',')
    if (client_ip not in white_listed_ips):
        return 'Error: Unauthorized IP', 403
    refresh_attribute = request.cookies.get('refresh_token')
    if not refresh_attribute:
        return 'Error: No refresh token provided', 401
    try:
        new_tokens = get_new_oauth_tokens(refresh_attribute)
        if new_tokens:
            response = make_response(jsonify({'access_token': new_tokens['access_token']}))
            response.set_cookie('id_token', new_tokens['id_token'], httponly=True, secure=True, samesite='None')
            response.set_cookie('access_token', new_tokens['access_token'], httponly=True, secure=True, samesite='None')
            response.set_cookie('refresh_token', new_tokens['refresh_token'], httponly=True, secure=True, samesite='None')
            return response, 200
        return 'Error: Unable to fetch the new tokens', 400
    except Exception as e:
        return f'Error: {str(e)}', 500

@app.route('/health', methods=['GET'])
def health():
    logging.info('Somebody just hit the /health endpoint!')
    return jsonify({'healthy': True}), 200

@app.route('/verify', methods=['GET'])
@cross_origin(origins=[Config.FE_DOMAIN], supports_credentials=True)
def token_verify():
    logging.info('Somebody just hit the /verify endpoint!')
    access_token = request.cookies.get('access_token')
    verdict = verify_token(access_token)
    logger.debug(f'Verdict: {verdict}')
    if verdict == 200:
        return jsonify({'valid': True, 'access_token': access_token}), 200
    return jsonify({'valid': False}), 401