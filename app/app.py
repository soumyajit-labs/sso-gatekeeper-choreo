import socket
import logging
from flask import Flask, request, redirect, make_response
from flask_cors import cross_origin
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from app.utils.access_tokens import get_oauth_tokens, get_new_oauth_tokens
from app.utils.saml_assert import encode_saml_assert, validate_saml_response, load_certificate
from app.utils.user_attributes import extract_user_data_from_saml
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
HOME = Config.HOME

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
    if request.endpoint in ['sso','health']:
        return
    try:
        csrf_token = request.cookies.get('csrf_token')
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
    okta_ips = [addr[-1] for addr in socket.getaddrinfo(OKTA_DOMAIN, None)]
    '''
    The part '(client_ip != HOME)' is an exemption for local testing
    The same goes for the variable named 'HOME' (line - 17)
    Both of these needs to be removed ASAP!
    '''
    if ((client_ip not in okta_ips) and (client_ip != HOME)):
        return 'Error: Unauthorized IP', 403
    saml_response = request.form.get('SAMLResponse')
    saml_code = encode_saml_assert(saml_response)
    certificate = load_certificate('assets/okta_cert_sha2.cert')
    try:
        if validate_saml_response(saml_response, certificate):
            '''
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

@app.route('/refresh', methods=['POST'])
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
            response = make_response('Success: New tokens fetched')
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
    return 'Hello there! I hope you are well! Adding some text!', 200

if __name__ == '__main__':
    app.run(debug=Config.DEBUG_FLAG)