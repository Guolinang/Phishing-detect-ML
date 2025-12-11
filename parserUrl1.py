#pip install requests
#pip install tldextract
#pip install whois
#pip install dnspython
#pip install regex
#pip install kagglehub

import re
import pandas as pd
from urllib.parse import urlparse, quote
import requests
import ssl
import socket
from datetime import datetime
import whois
from bs4 import BeautifulSoup
import dns.resolver
import os
import urllib.request
import logging  
import logging
logging.basicConfig(level=logging.CRITICAL)
logging.basicConfig(filename='parser_errors.log', level=logging.ERROR)

features = {
              'having_IPhaving_IP_Address': 0,
              'URLURL_Length': 0,
              'Shortining_Service': 0,
              'having_At_Symbol': 0,
              'double_slash_redirecting': 0,
              'Prefix_Suffix': 0,
              'having_Sub_Domain': 0,
              'SSLfinal_State': 0,
              'Domain_registeration_length': 0,
              'Favicon': 0,
              'port': 0,
              'HTTPS_token': 0,
              'Request_URL': 0,
              'URL_of_Anchor': 0,
              'Links_in_tags': 0,
              'SFH': 0,
              'Submitting_to_email': 0,
              'Abnormal_URL': 0,
              'Redirect': 0,
              'on_mouseover': 0,
              'RightClick': 0,
              'popUpWidnow': 0,
              'Iframe': 0,
              'age_of_domain': 0,
              'DNSRecord': 0,
              'web_traffic': 0,
              'Page_Rank': 0,
              'Google_Index': 0,
              'Links_pointing_to_page': 0,
              'Statistical_report ': 0}

def having_IP(domain):
    ipv4_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    ipv6_pattern = re.compile(r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$')
    hex_pattern = re.compile(r'^0x[0-9a-fA-F]+$')
    
    if ipv4_pattern.match(domain) or ipv6_pattern.match(domain) or hex_pattern.match(domain):
        features['having_IPhaving_IP_Address'] = -1
    else:
        features['having_IPhaving_IP_Address'] = 1

def URL_check(url):
    parts = urlparse(url)
    url_string = url
    domain_string = parts.hostname
    path = parts.path
    port = parts.port
    scheme = parts.scheme

    if len(url_string) > 75:
        features['URLURL_Length'] = -1
    elif 54 <= len(url_string) <= 75:
        features['URLURL_Length'] = 0
    else:
        features['URLURL_Length'] = 1

    if '@' in url_string:
        features['having_At_Symbol'] = -1
    else:
        features['having_At_Symbol'] = 1

    start_pos = len(scheme) + 3  
    if url_string.find('//', start_pos) != -1:
        features['double_slash_redirecting'] = -1
    else:
        features['double_slash_redirecting'] = 1

    if '-' in domain_string:
        features['Prefix_Suffix'] = -1
    else:
        features['Prefix_Suffix'] = 1

    domain = domain_string.lstrip('www.')  
    dots = domain.count('.')
    if dots > 2:
        features['having_Sub_Domain'] = -1
    elif dots == 2:
        features['having_Sub_Domain'] = 0
    else:
        features['having_Sub_Domain'] = 1

    if port is None:
        port = 443 if scheme == 'https' else 80 if scheme == 'http' else None
    if port in (80, 443) or port is None:
        features['port'] = 1
    else:
        features['port'] = -1

    if 'https' in domain_string:
        features['HTTPS_token'] = -1
    else:
        features['HTTPS_token'] = 1

def url_shortened(url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }

    shorteners = ['bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly', 't.co', 'tinyurl.com', 'ow.ly', 'bitly.com', 'tiny.cc', 'adf.ly', 'bit.do', 'mcaf.ee', 'is.gd', 'buff.ly', 'su.pr']  # expanded list

    parts = urlparse(url)
    domain = parts.hostname

    if domain.lower() in [d.lower() for d in shorteners]:
        features["Shortining_Service"] = -1
    else:
        features["Shortining_Service"] = 1

    try:
        response = requests.head(url, headers=headers, allow_redirects=True, timeout=10)
        response.raise_for_status()
        redirects = len(response.history)

        if redirects >= 4:
            features["Redirect"] = -1
        elif redirects >= 2:
            features["Redirect"] = 0
        else:
            features["Redirect"] = 1
        return

    except requests.RequestException:
        features["Shortining_Service"] = -1
        features["Redirect"] = -1
        return
    except Exception:
        logging.error(f"Unexpected error in url_shortened for {url}")
        features["Shortining_Service"] = -1
        features["Redirect"] = -1
        return

def SSLfinal_State(domain):
    current_date = datetime.now().replace(tzinfo=None)
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                certificate = ssock.getpeercert()
                cert_expiry = datetime.strptime(certificate['notAfter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=None)
                cert_creation = datetime.strptime(certificate['notBefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=None)
                issuer = dict(x[0] for x in certificate['issuer'])
                issued_by = issuer.get('organizationName', '')
                if 'Let\'s Encrypt' in issued_by or 'Amazon' in issued_by or 'Google Trust Services' in issued_by:
                    features['SSLfinal_State'] = 0
                else:
                    if (cert_expiry - current_date).days > 365:
                        features['SSLfinal_State'] = 1
                    else:
                        features['SSLfinal_State'] = 0
    except socket.gaierror:
        features['SSLfinal_State'] = -1
        return
    except ssl.SSLError:
        features['SSLfinal_State'] = -1
        return
    except socket.timeout:
        features['SSLfinal_State'] = -1
        return
    except Exception:
        logging.error(f"Unexpected error in SSLfinal_State for {domain}")
        features['SSLfinal_State'] = -1
        return
    
def time_domain(domain):
    try:
        domain_info = whois.whois(domain)
        
        # Handle creation_date being a list
        if isinstance(domain_info.creation_date, list):
            createDate = domain_info.creation_date[0].replace(tzinfo=None)
        else:
            createDate = domain_info.creation_date.replace(tzinfo=None)
            
        # FIX for TypeError: Handle expiration_date being a list (similar to creation_date)
        if isinstance(domain_info.expiration_date, list):
            expireDate = domain_info.expiration_date[0].replace(tzinfo=None)
        else:
            expireDate = domain_info.expiration_date.replace(tzinfo=None)
        
        current_date = datetime.now().replace(tzinfo=None)
        age_days = (current_date - createDate).days
        
        if age_days >= 182:  # примерно 6 месяцев
            features['age_of_domain'] = 1
        else:
            features['age_of_domain'] = -1
        
        features['Domain_registeration_length'] = 1 if (expireDate - current_date).days >= 365 else -1
        return
    except Exception as e:
        logging.error(f"Error in time_domain for {domain}: {e}")
        features['age_of_domain'] = -1
        features['Domain_registeration_length'] = -1
        return
    
def favicon_check(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        favicon_link = soup.find("link", rel="shortcut icon") or soup.find("link", rel="icon")
        if favicon_link:
            favicon_href = favicon_link['href']
            if urlparse(favicon_href).netloc != urlparse(url).netloc:
                features['Favicon'] = -1
                return
        features['Favicon'] = 1
    except requests.RequestException:
        features['Favicon'] = -1
        return
    except Exception:
        logging.error(f"Unexpected error in favicon_check for {url}")
        features['Favicon'] = -1
        return
    
def get_external_domains_static(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        main_domain = urlparse(url).netloc

        total_resources = 0
        external_resources = 0

        total_anchors = 0
        external_anchors = 0

        total_tags = 0  
        external_tags = 0

        has_form = False
        sfh_same = 0
        sfh_other = 0
        sfh_empty = 0

        submitting_to_email = False

        anchors = soup.find_all('a', href=True)
        total_anchors = len(anchors)
        for a in anchors:
            href = a['href']
            if href.startswith('#') or href == '' or 'javascript:void(0)' in href:
                external_anchors += 1  
            elif href.startswith(('http://', 'https://')):
                parsed = urlparse(href)
                if parsed.netloc and parsed.netloc != main_domain:
                    external_anchors += 1

        resources_tags = ['img', 'audio', 'embed', 'iframe', 'video', 'source', 'track']
        for tag in resources_tags:
            for element in soup.find_all(tag, src=True):
                src = element['src']
                total_resources += 1
                if src.startswith(('http://', 'https://')):
                    parsed = urlparse(src)
                    if parsed.netloc and parsed.netloc != main_domain:
                        external_resources += 1

        for form in soup.find_all('form', action=True):
            has_form = True
            action = form['action']
            if action == '' or action == 'about:blank':
                sfh_empty += 1
            elif action.startswith(('http://', 'https://', 'mailto:')):
                parsed = urlparse(action)
                if parsed.scheme == 'mailto':
                    submitting_to_email = True
                if parsed.netloc and parsed.netloc != main_domain:
                    sfh_other += 1
            else:
                sfh_same += 1  

        tags = ['meta', 'script', 'link']
        for tag in tags:
            attr = 'content' if tag == 'meta' else 'src' if tag == 'script' else 'href'
            for element in soup.find_all(tag, **{attr: True}):
                resource_url = element[attr]
                total_tags += 1
                if resource_url.startswith(('http://', 'https://')):
                    parsed = urlparse(resource_url)
                    if parsed.netloc and parsed.netloc != main_domain:
                        external_tags += 1


        if total_resources > 0:
            perc_external_res = external_resources / total_resources
            if perc_external_res < 0.31:
                features["Request_URL"] = 1
            elif perc_external_res < 0.67:
                features["Request_URL"] = 0
            else:
                features["Request_URL"] = -1
        else:
            features["Request_URL"] = 1


        if total_anchors > 0:
            perc_external_a = external_anchors / total_anchors
            if perc_external_a < 0.31:
                features["URL_of_Anchor"] = 1
            elif perc_external_a < 0.67:
                features["URL_of_Anchor"] = 0
            else:
                features["URL_of_Anchor"] = -1
        else:
            features["URL_of_Anchor"] = 1


        if total_tags > 0:
            perc_external_tags = external_tags / total_tags
            if perc_external_tags < 0.17:
                features["Links_in_tags"] = 1
            elif perc_external_tags < 0.81:
                features["Links_in_tags"] = 0
            else:
                features["Links_in_tags"] = -1
        else:
            features["Links_in_tags"] = 1


        total_sfh = sfh_same + sfh_other + sfh_empty
        if total_sfh > 0:
            if sfh_empty > 0:
                features["SFH"] = -1
            elif sfh_other > 0:
                features["SFH"] = 0
            else:
                features["SFH"] = 1
        elif has_form:
            features["SFH"] = -1 
        else:
            features["SFH"] = 1  
        if submitting_to_email:
            features["Submitting_to_email"] = -1
        else:
            features["Submitting_to_email"] = 1

        onmouseover_elements = soup.find_all(attrs={"onmouseover": True})
        status_change = False
        for elem in onmouseover_elements:
            if 'window.status' in elem['onmouseover'].lower():
                status_change = True
                break
        if status_change:
            features["on_mouseover"] = -1
        else:
            features["on_mouseover"] = 1

        iframes = soup.find_all('iframe')
        invisible_iframe = False
        for iframe in iframes:
            if iframe.get('frameborder') == '0' or 'border:0' in iframe.get('style', '').lower() or 'border:none' in iframe.get('style', '').lower():
                invisible_iframe = True
                break
        if invisible_iframe:
            features["Iframe"] = -1
        else:
            features["Iframe"] = 1

        return

    except Exception as e:
        print(f"Error: {e}")
        features["Request_URL"] = -1
        features["URL_of_Anchor"] = -1
        features["Links_in_tags"] = -1
        features["SFH"] = -1
        features["Submitting_to_email"] = -1
        features["Iframe"] = -1
        features["on_mouseover"] = -1
        return

def dns_check(domain):
    try:
        dns.resolver.resolve(domain, 'A')
        features['DNSRecord'] = 1
    except dns.resolver.NXDOMAIN:
        features['DNSRecord'] = -1
        return
    except dns.resolver.NoAnswer:
        features['DNSRecord'] = -1
        return
    except dns.resolver.Timeout:
        features['DNSRecord'] = -1
        return
    except dns.exception.DNSException:
        features['DNSRecord'] = -1
        return
    except Exception:
        logging.error(f"Unexpected error in dns_check for {domain}")
        features['DNSRecord'] = -1
        return

def url_google_index(url):
    search_url = f"https://www.google.com/search?q=site:{quote(url)}"
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    try:
        response = requests.get(search_url, headers=headers, timeout=10)
        response.raise_for_status()
        if "ничего не найдено" not in response.text.lower() and "no results found" not in response.text.lower():
            features['Google_Index'] = 1
        else:
            features['Google_Index'] = -1
    except requests.RequestException:
        features['Google_Index'] = -1
        return
    except Exception:
        logging.error(f"Unexpected error in url_google_index for {url}")
        features['Google_Index'] = -1
        return
    
def traffic_check(domain):
    try:
        # Пример API для трафика, адаптировать если нужно
        url = f"https://api.similarweb.com/v1/website/{domain}/global-rank?api_key=your_key"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        rank = data.get('global_rank', 0)
        if rank > 100000:
            features['web_traffic'] = -1
        elif rank > 10000:
            features['web_traffic'] = 0
        else:
            features['web_traffic'] = 1
    except requests.RequestException:
        features['web_traffic'] = -1
        return
    except Exception:
        logging.error(f"Unexpected error in traffic_check for {domain}")
        features['web_traffic'] = -1
        return

def statistical_check(domain):
    file_path = 'online-valid.csv'
    url = "https://data.phishtank.com/data/online-valid.csv"
    try:
        urllib.request.urlretrieve(url, file_path)
    except Exception:
        logging.error(f"Error downloading PhishTank data for {domain}")
        features['Statistical_report'] = 0 
        return
    try:
        df = pd.read_csv(file_path)
        urls = df['url']
        is_phishing = any(domain == urlparse(u).netloc for u in urls)
        features['Statistical_report'] = -1 if is_phishing else 1
    except Exception:
        logging.error(f"Error reading PhishTank data for {domain}")
        features['Statistical_report'] = 0
        return
def pagerank_check(domain):
    API_KEY = "4sgoc80o4ggw0ccccgkgcgsw80ocoo4osw0gg4gk"  # Assuming valid
    url = "https://openpagerank.com/api/v1.0/getPageRank"
    params = [("domains[]", domain)]
    headers = {"API-OPR": API_KEY}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        for item in data.get("response", []):
            pr = item.get("page_rank_decimal", 0) / 10.0 
            if pr <= 0.5:
                features['Page_Rank'] = -1
                features['Links_pointing_to_page'] = -1
            else:
                features['Page_Rank'] = -1
                features['Links_pointing_to_page'] = -1
    except requests.RequestException:
        features['Page_Rank'] = -1
        features['Links_pointing_to_page'] = -1
        return
    except Exception:
        logging.error(f"Unexpected error in pagerank_check for {domain}")
        features['Page_Rank'] = -1
        features['Links_pointing_to_page'] = -1
        return

def rightclick_check(url, timeout=10):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')

        disabled = False

        if soup.body and soup.body.get('oncontextmenu') == 'return false;':
            disabled = True

        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and 'contextmenu' in script.string.lower() and 'preventDefault' in script.string:
                disabled = True

        patterns = [
            r'oncontextmenu\s*=\s*["\']return false;["\']',
            r'addEventListener\s*\(\s*["\']contextmenu["\']',
            r'contextmenu\s*:\s*function\s*\(e\)\s*{\s*e\.preventDefault\(\)'
        ]
        compiled_patterns = [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in patterns]

        for pattern in compiled_patterns:
            if pattern.search(response.text):
                disabled = True

        features['RightClick'] = -1 if disabled else 1

    except requests.RequestException:
        features['RightClick'] = -1
        return
    except Exception:
        logging.error(f"Unexpected error in rightclick_check for {url}")
        features['RightClick'] = -1
        return

def popup_window_check(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')

        has_popup_with_input = False
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                if 'window.open' in script.string.lower() and ('prompt(' in script.string.lower() or 'input' in script.string.lower()):
                    has_popup_with_input = True
                    break

        features['popUpWidnow'] = -1 if has_popup_with_input else 1
    except requests.RequestException:
        features['popUpWidnow'] = -1
        return
    except Exception:
        logging.error(f"Unexpected error in popup_window_check for {url}")
        features['popUpWidnow'] = -1
        return

def parse_string(url):
    parts = urlparse(url)
    domain = parts.hostname
    
    try:
        socket.getaddrinfo(domain, None) 
    except socket.gaierror:
        features['Shortining_Service'] = -1
        features['Redirect'] = -1
        features['SSLfinal_State'] = -1
        features['Domain_registeration_length'] = -1
        features['Favicon'] = -1
        features['DNSRecord'] = -1
        features['Google_Index'] = -1
        features['web_traffic'] = -1
        features['Page_Rank'] = -1
        features['Links_pointing_to_page'] = -1
        features['Statistical_report'] = 0
        features['RightClick'] = -1
        features['popUpWidnow'] = -1
        features['age_of_domain'] = -1
        URL_check(url)
        having_IP(domain)
        get_external_domains_static(url) 
        return features
    URL_check(url)
    having_IP(domain)
    url_shortened(url)
    SSLfinal_State(domain)
    time_domain(domain)
    favicon_check(url)
    get_external_domains_static(url)
    dns_check(domain)
    url_google_index(url)
    traffic_check(domain)
    statistical_check(domain)
    pagerank_check(domain)
    rightclick_check(url)
    popup_window_check(url)
    return features
