import base64
from lxml import etree
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate

def load_certificate(cert_path):
    with open(cert_path, 'rb') as f:
        return load_pem_x509_certificate(f.read())

def validate_saml_response(saml_response, certificate):
    saml_xml = base64.b64decode(saml_response)
    root = etree.fromstring(saml_xml)

    sign_value = root.find('.//{http://www.w3.org/2000/09/xmldsig#}SignatureValue')
    if sign_value is None:
        raise ValueError('Signature not found in the SAML response')
    try:
        signature_value = base64.b64decode(sign_value.text.strip())
    except Exception as e:
        raise ValueError('Error for Signature Value: ', e)

    signed_info = root.find('.//{http://www.w3.org/2000/09/xmldsig#}SignedInfo')
    if signed_info is None:
        raise ValueError('No Signed Info element found in SAML response')
    try:
        signed_info_canonical = etree.tostring(signed_info, method='c14n', exclusive=True, with_comments=False)
    except Exception as e:
        raise ValueError('Error for Signed Info: ', e)
    
    try:
        cert = certificate.public_key()
        cert.verify(
            signature_value,
            signed_info_canonical,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        raise ValueError('Signature verification failed: ' + str(e))

def encode_saml_assert(saml_response):
    saml_xml = base64.b64decode(saml_response)
    root = etree.fromstring(saml_xml)
    signature_element = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
    signature_value = etree.tostring(signature_element)
    return (base64.b64encode(signature_value))