from  urllib.parse import urlparse 
import re
from urllib.parse import unquote, quote
from datetime import datetime
import urllib.request
import socket
import time
import dns.resolver
import dns.rdatatype
from googlesearch import search
import tldextract
from typing import Union, Dict, List
import ssl
import whois
import requests
from ping3 import ping
import tldextract

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
    "qty_tld_url": 0,
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
    "domain_in_ip": 0,
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
    "qty_ip_resolved": 0,
    "qty_nameservers": 0,
    "qty_mx_servers": 0,
    "ttl_hostname": 0,
    "tls_ssl_certificate": 0,
    "qty_redirects": 0,
    "url_google_index": 0,
    "domain_google_index": 0,
    "url_shortened": 0    
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
    



def find_email(url):    
    decoded_url = unquote(url)
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'    
    emails_found = re.findall(email_pattern, decoded_url)    
    return 1 if emails_found else 0

def measure_time_response(url):
    start_time = time.time()
    try : 
        urllib.request.urlopen(url, timeout=10)
    except Exception as e:
        print(e)  
        return -1
    end_time = time.time()
    return (end_time - start_time) 




def spf_domain(domain):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '8.8.4.4'] 
    resolver.timeout = 10  
    try:
        answers = resolver.resolve(domain, 'TXT')
        
        spf_found = False
        for rdata in answers:
            txt_record = ''.join([s.decode('utf-8') for s in rdata.strings])
            if txt_record.startswith('v=spf1'):
                spf_found = True
                break

        if spf_found:
            features['domain_spf'] = 1
        else:
            features['domain_spf'] = 0
        return
        
    except dns.resolver.NoAnswer:
        features['domain_spf'] = 0
        return
    except Exception as e:
        features['domain_spf'] = 0
        print(e)
        return
    
def asn_ip(string):
    ip=socket.gethostbyname(string)
    
    try:
        url = f"https://api.hackertarget.com/aslookup/?q={ip}"
        response = requests.get(url, timeout=10)
        data = response.text.strip()
        features["asn_ip"]=int(data.split(",")[1].strip('"'))
         
    except Exception as e:
        print(e) 
        features["asn_ip"]=-1
        return 

def time_domain(string):
    try:         
        domain_info = whois.whois(string)
        
        if isinstance(domain_info.creation_date, list):
            createDate = domain_info.creation_date[0].replace(tzinfo=None)
        else:
            createDate = domain_info.creation_date.replace(tzinfo=None)        
        if isinstance(domain_info.expiration_date, list):
            expiredDate = domain_info.expiration_date[0].replace(tzinfo=None)
        else:
            expiredDate = domain_info.expiration_date.replace(tzinfo=None)
        
        today = datetime.now().replace(tzinfo=None)        
        features['time_domain_activation'] = (today - createDate).days
        features['time_domain_expiration'] = (expiredDate - today).days
        return
        
    except Exception as e:
        print(e)         
        features['time_domain_activation'] = -1
        features['time_domain_expiration'] = -1
        return
    
def qty_ip_resolved(domain):      
    try:
        ip_list = socket.getaddrinfo(domain, None)
        ip_addresses = set([ip[4][0] for ip in ip_list])
        features['qty_ip_resolved'] = len(ip_addresses)
        return
    except Exception as e:
        print(e)     
        features['qty_ip_resolved']=-1
        return 0

def qty_nameservers(domain):
    try:
        answer = dns.resolver.resolve(domain, 'NS')
        nameservers = [ns.target.to_text() for ns in answer]
        features['qty_nameservers'] = len(nameservers)
        return
    except Exception as e:
        print(e)     
        features['qty_nameservers']=-1
        return

def qty_mx_servers(domain):
    try:
        answer = dns.resolver.resolve(domain, 'MX')
        mx_servers = []
        for mx in answer:
            server = mx.exchange.to_text()
            priority = mx.preference
            mx_servers.append((priority, server))
        features['qty_mx_servers'] = len(mx_servers)
        return
    except Exception as e:
        print(e)     
        features['qty_mx_servers']=-1
        return

def ttl_hostname(domain):
    try:
       
        answer = dns.resolver.resolve(domain, 'A')
        ttl = answer.rrset.ttl
        for rrset in answer.response.answer:
            if rrset.rdtype == dns.rdatatype.A:
                ttl = rrset.ttl
                break
        features['ttl_hostname'] = ttl
        return
    except Exception as e:
        print(e)     
        features['ttl_hostname']=-1
        return
    
def tls_ssl_certificate(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                certificate = ssock.getpeercert()
        features['tls_ssl_certificate']=1
        return 
    except Exception as e:
        print(e)     
        features['tls_ssl_certificate']=0
        return

def qty_redirects(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        features['qty_redirects'] = len(response.history)
        return
    except Exception as e:
        print(e)     
        features['qty_redirects']=-1
        return

def url_google_index(url):
    search_url = f"https://www.google.com/search?q=site:{quote(url)}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        response = requests.get(search_url, headers=headers)
        if "ничего не найдено" not in response.text.lower() and "no results found" not in response.text.lower():
            features['url_google_index']=1
            return
        else:
            features['url_google_index']=0
            return 
    except Exception as e:
        print(e)     
        features['url_google_index']=-1
        return

def domain_google_index(domain):
    search_url = f"https://www.google.com/search?q=site:{quote(domain)}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        response = requests.get(search_url, headers=headers)
        if "ничего не найдено" not in response.text.lower() and "no results found" not in response.text.lower():
            features['domain_google_index']=1
            return
        else:
            features['domain_google_index']=0
            return 
    except Exception as e:
        print(e)     
        features['domain_google_index']=-1
        return

def url_shortened(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        if  (response.url == url):
           features["url_shortened"]=0
           return
        else:
           features["url_shortened"]=1
           return
    except Exception as e:
        features["url_shortened"]=0
        print(e)
        return 

def domain_in_ip(domain):
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
    if re.match(ipv6_pattern, domain) or re.match(ipv4_pattern, domain):
        features["domain_in_ip"]=1
    else:
        features["domain_in_ip"]=0

def qty_tld_url(url):
    try:
        extracted = tldextract.extract(url)
        tld = extracted.suffix
        
        if not tld:
            features["qty_tld_url"] = 0
            return
        
        tld_parts = tld.split('.')
        features["qty_tld_url"] = len(tld_parts)
        return
        
    except Exception as e:
        features["qty_tld_url"] = 0
        print(e)
        return

def server_client_domain(url):
    try:
        extracted = tldextract.extract(url)
        domain = extracted.domain.lower()
        
        if 'server' in domain or 'client' in domain:
            features["server_client_domain"] = 1
            return
        else:
            features["server_client_domain"] = 0
            return
            
    except Exception as e:
        features["server_client_domain"] = 0
        print(e)
        return

def parse_string(string):
    parts = urlparse(string)
    domain_string=parts.hostname

    count_symbols(string)
    features['email_in_url'] = find_email(string)
    features['time_response'] = measure_time_response(string)
    server_client_domain(string)
    qty_tld_url(string)
    domain_in_ip(domain_string)
    spf_domain(domain_string)
    asn_ip(domain_string)
    time_domain(domain_string)
    qty_ip_resolved(domain_string)
    qty_nameservers(domain_string)
    qty_mx_servers(domain_string)
    ttl_hostname(domain_string)
    tls_ssl_certificate(domain_string)
    qty_redirects(string)
    url_google_index(string)
    domain_google_index(domain_string)
    url_shortened(string)
    return features




#   pip install python-whois
#   pip install ipwhois
#   pip install whois
#   pip install dnspython
#   pip install ping3
#   pip install requests

   
        

