import base64
from lxml import etree

def extract_user_data_from_saml(saml_response):
    saml_xml = base64.b64decode(saml_response)
    root = etree.fromstring(saml_xml)
    namespaces = {
        'saml2': 'urn:oasis:names:tc:SAML:2.0:assertion',
        'saml2p': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'ds': 'http://www.w3.org/2000/09/xmldsig#',
    }

    assertion_node = root.find('.//saml2:Assertion', namespaces)
    if assertion_node is None:
        raise ValueError('No Assertion element found in SAML response')

    attributes = {}
    attribute_nodes = assertion_node.findall('.//saml2:Attribute', namespaces)
    if not attribute_nodes:
        raise ValueError('No Attribute elements found in SAML assertion')

    for attribute_node in attribute_nodes:
        attr_name = attribute_node.get('Name')
        if not attr_name:
            continue
        for attr_value in attribute_node.findall('.//saml2:AttributeValue', namespaces):
            attributes[attr_name] = [attr_value.text]
    return attributes