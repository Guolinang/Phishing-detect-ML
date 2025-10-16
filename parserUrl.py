from  urllib.parse import urlparse 
import re
from urllib.parse import unquote
import urllib.request
import time


features = {
    # URL features
    "url_dot": 0,
    "url_hyphen": 0,
    "url_underscore": 0,
    "url_slash": 0,
    "url_question": 0,
    "url_equal": 0,
    "url_at": 0,
    "url_ampersand": 0,
    "url_exclamation": 0,
    "url_space": 0,
    "url_tilde": 0,
    "url_comma": 0,
    "url_plus": 0,
    "url_asterisk": 0,
    "url_hash": 0,
    "url_dollar": 0,
    "url_percent": 0,
    "url_tld": 0,
    "len_url": 0,
    
    # Domain features
    "domain_dot": 0,
    "domain_hyphen": 0,
    "domain_underscore": 0,
    "domain_slash": 0,
    "domain_question": 0,
    "domain_equal": 0,
    "domain_at": 0,
    "domain_ampersand": 0,
    "domain_exclamation": 0,
    "domain_space": 0,
    "domain_tilde": 0,
    "domain_comma": 0,
    "domain_plus": 0,
    "domain_asterisk": 0,
    "domain_hash": 0,
    "domain_dollar": 0,
    "domain_percent": 0,
    "domain_vowels": 0,
    "len_domain": 0,
    "server_client_domain": 0,
    
    # Directory features
    "directory_dot": 0,
    "directory_hyphen": 0,
    "directory_underscore": 0,
    "directory_slash": 0,
    "directory_question": 0,
    "directory_equal": 0,
    "directory_at": 0,
    "directory_ampersand": 0,
    "directory_exclamation": 0,
    "directory_space": 0,
    "directory_tilde": 0,
    "directory_comma": 0,
    "directory_plus": 0,
    "directory_asterisk": 0,
    "directory_hash": 0,
    "directory_dollar": 0,
    "directory_percent": 0,
    "directory_length": 0,
    
    # File features
    "file_dot": 0,
    "file_hyphen": 0,
    "file_underscore": 0,
    "file_slash": 0,
    "file_question": 0,
    "file_equal": 0,
    "file_at": 0,
    "file_ampersand": 0,
    "file_exclamation": 0,
    "file_space": 0,
    "file_tilde": 0,
    "file_comma": 0,
    "file_plus": 0,
    "file_asterisk": 0,
    "file_hash": 0,
    "file_dollar": 0,
    "file_percent": 0,
    "file_length": 0,
    
    # Parameters features
    "params_dot": 0,
    "params_hyphen": 0,
    "params_underscore": 0,
    "params_slash": 0,
    "params_question": 0,
    "params_equal": 0,
    "params_at": 0,
    "params_ampersand": 0,
    "params_exclamation": 0,
    "params_space": 0,
    "params_tilde": 0,
    "params_comma": 0,
    "params_plus": 0,
    "params_asterisk": 0,
    "params_hash": 0,
    "params_dollar": 0,
    "params_percent": 0,
    "params_length": 0,
    
    # Other features
    "email_in_url": 0,
    "time_response": 0,
    "domain_spf": 0,
    "asn_ip": 0,
    "time_domain_activation": 0,
    "time_domain_expiration": 0,
    "qty_ip_resolve": 0,
    "qty_nameservers": 0,
    "qty_mx_servers": 0,
    "ttl_hostname": 0,
    "tls_ssl_certificate": 0,
    "qty_redirects": 0,
    "url_google_index": 0,
    "domain_google_index": 0,
    "url_shortened": 0,
    "phishing": 0
}

def count_symbols(string):
    parts = urlparse(string)
    url_string=string
    domain_string=parts.hostname
    path = parts.path
    if '/' in path:
        directory_string = '/'.join(path.split('/')[:-1])
        if path.startswith('/') and not directory_string.startswith('/'):
            directory_string = '/' + directory_string
    else:
        directory_string = ""
    file_string = path.split('/')[-1] if path and path != '/' else ""
    params_string = parts.query

    # Для URL
    for char in url_string:
        match char:
            case '.': features['url_dot'] += 1
            case '-': features['url_hyphen'] += 1
            case '_': features['url_underscore'] += 1
            case '/': features['url_slash'] += 1
            case '?': features['url_question'] += 1
            case '=': features['url_equal'] += 1
            case '@': features['url_at'] += 1
            case '&': features['url_ampersand'] += 1
            case '!': features['url_exclamation'] += 1
            case ' ': features['url_space'] += 1
            case '~': features['url_tilde'] += 1
            case ',': features['url_comma'] += 1
            case '+': features['url_plus'] += 1
            case '*': features['url_asterisk'] += 1
            case '#': features['url_hash'] += 1
            case '$': features['url_dollar'] += 1
            case '%': features['url_percent'] += 1

    features['len_url'] = len(url_string)

    # Для Domain
    vowels = "aeiouаеёиоуыэюя"
    
    for char in domain_string:
        match char:
            case '.': features['domain_dot'] += 1
            case '-': features['domain_hyphen'] += 1
            case '_': features['domain_underscore'] += 1
            case '/': features['domain_slash'] += 1
            case '?': features['domain_question'] += 1
            case '=': features['domain_equal'] += 1
            case '@': features['domain_at'] += 1
            case '&': features['domain_ampersand'] += 1
            case '!': features['domain_exclamation'] += 1
            case ' ': features['domain_space'] += 1
            case '~': features['domain_tilde'] += 1
            case ',': features['domain_comma'] += 1
            case '+': features['domain_plus'] += 1
            case '*': features['domain_asterisk'] += 1
            case '#': features['domain_hash'] += 1
            case '$': features['domain_dollar'] += 1
            case '%': features['domain_percent'] += 1
            
        if char.lower() in vowels:
            features['domain_vowels'] += 1

    if domain_string.find("server") or (domain_string.find("client")) :
        features['domain_server_client'] = 1

    features['len_domain'] = len(domain_string)

    # Для Directory
    for char in directory_string:
        match char:
            case '.': features['directory_dot'] += 1
            case '-': features['directory_hyphen'] += 1
            case '_': features['directory_underscore'] += 1
            case '/': features['directory_slash'] += 1
            case '?': features['directory_question'] += 1
            case '=': features['directory_equal'] += 1
            case '@': features['directory_at'] += 1
            case '&': features['directory_ampersand'] += 1
            case '!': features['directory_exclamation'] += 1
            case ' ': features['directory_space'] += 1
            case '~': features['directory_tilde'] += 1
            case ',': features['directory_comma'] += 1
            case '+': features['directory_plus'] += 1
            case '*': features['directory_asterisk'] += 1
            case '#': features['directory_hash'] += 1
            case '$': features['directory_dollar'] += 1
            case '%': features['directory_percent'] += 1

    features['directory_length'] = len(directory_string)

    # Для File
    for char in file_string:
        match char:
            case '.': features['file_dot'] += 1
            case '-': features['file_hyphen'] += 1
            case '_': features['file_underscore'] += 1
            case '/': features['file_slash'] += 1
            case '?': features['file_question'] += 1
            case '=': features['file_equal'] += 1
            case '@': features['file_at'] += 1
            case '&': features['file_ampersand'] += 1
            case '!': features['file_exclamation'] += 1
            case ' ': features['file_space'] += 1
            case '~': features['file_tilde'] += 1
            case ',': features['file_comma'] += 1
            case '+': features['file_plus'] += 1
            case '*': features['file_asterisk'] += 1
            case '#': features['file_hash'] += 1
            case '$': features['file_dollar'] += 1
            case '%': features['file_percent'] += 1

    features['file_length'] = len(file_string)

    # Для Parameters
    for char in params_string:
        match char:
            case '.': features['params_dot'] += 1
            case '-': features['params_hyphen'] += 1
            case '_': features['params_underscore'] += 1
            case '/': features['params_slash'] += 1
            case '?': features['params_question'] += 1
            case '=': features['params_equal'] += 1
            case '@': features['params_at'] += 1
            case '&': features['params_ampersand'] += 1
            case '!': features['params_exclamation'] += 1
            case ' ': features['params_space'] += 1
            case '~': features['params_tilde'] += 1
            case ',': features['params_comma'] += 1
            case '+': features['params_plus'] += 1
            case '*': features['params_asterisk'] += 1
            case '#': features['params_hash'] += 1
            case '$': features['params_dollar'] += 1
            case '%': features['params_percent'] += 1

    features['params_length'] = len(params_string)
    print(features)

def check_email_for_features(url):    
    decoded_url = unquote(url)
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'    
    emails_found = re.findall(email_pattern, decoded_url)    
    return 1 if emails_found else 0

def measure_time_response(url):
    start_time = time.time()
    try : 
        urllib.request.urlopen(url, timeout=10)
    except:
        return 10
    end_time = time.time()
    return (end_time - start_time) 

def parse_string(string):
    count_symbols("string")
    features['email_in_url'] = check_email_for_features(string)
    features['time_response'] = measure_time_response(string)





print(measure_time_response("https://www.kaggle.com/datasets/mdsultanulislamovi/phishing-website-detection-datasets?select=dataset2.csv"))



   
        

