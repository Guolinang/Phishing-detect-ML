# pip install tldextract
# pip install requests
# pip install beautifulsoup4
# pip install whois
# pip install dnspython
# pip install urllib3
# pip install Levenshtein 

import re
from urllib.parse import urlparse
import tldextract
import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver
import socket
import time
import ssl
import logging
from typing import Dict
import Levenshtein  

logging.basicConfig(filename='parser_errors.log', level=logging.ERROR)

features = {
    "URLLength": 0,
    "Domain": "",
    "DomainLength": 0,
    "IsDomainIP": 0,
    "TLD": "",
    "URLSimilarityIndex": 0.0,
    "CharContinuationRate": 0.0,
    "TLDLegitimateProb": 0.0,
    "URLCharProb": 0.0,
    "TLDLength": 0,
    "NoOfSubDomain": 0,
    "HasObfuscation": 0,
    "NoOfObfuscatedChar": 0,
    "ObfuscationRatio": 0.0,
    "NoOfLettersInURL": 0,
    "LetterRatioInURL": 0.0,
    "NoOfDegitsInURL": 0,
    "DegitRatioInURL": 0.0,
    "NoOfEqualsInURL": 0,
    "NoOfQMarkInURL": 0,
    "NoOfAmpersandInURL": 0,
    "NoOfOtherSpecialCharsInURL": 0,
    "SpacialCharRatioInURL": 0.0,
    "IsHTTPS": 0,
    "LineOfCode": 0,
    "LargestLineLength": 0,
    "HasTitle": 0,
    "Title": "",
    "DomainTitleMatchScore": 0.0,
    "URLTitleMatchScore": 0.0,
    "HasFavicon": 0,
    "Robots": 0,
    "IsResponsive": 0,
    "NoOfURLRedirect": 0,
    "NoOfSelfRedirect": 0,
    "HasDescription": 0,
    "NoOfPopup": 0,
    "NoOfiFrame": 0,
    "HasExternalFormSubmit": 0,
    "HasSocialNet": 0,
    "HasSubmitButton": 0,
    "HasHiddenFields": 0,
    "HasPasswordField": 0,
    "Bank": 0,
    "Pay": 0,
    "Crypto": 0,
    "HasCopyrightInfo": 0,
    "NoOfImage": 0,
    "NoOfCSS": 0,
    "NoOfJS": 0,
    "NoOfSelfRef": 0,
    "NoOfEmptyRef": 0,
    "NoOfExternalRef": 0
}

def extract_basic_features(url: str) -> None:
    parsed = urlparse(url)
    domain = parsed.netloc
    extracted = tldextract.extract(url)
    tld = extracted.suffix
    
    features["URLLength"] = len(url)
    features["Domain"] = domain
    features["DomainLength"] = len(domain)
    features["TLD"] = tld
    features["TLDLength"] = len(tld)
    features["NoOfSubDomain"] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
    
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
    features["IsDomainIP"] = 1 if re.match(ipv4_pattern, domain) or re.match(ipv6_pattern, domain) else 0
    
    features["IsHTTPS"] = 1 if parsed.scheme == 'https' else 0
    
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    equals = url.count('=')
    qmarks = url.count('?')
    ampersands = url.count('&')
    specials = len(re.findall(r'[^a-zA-Z0-9]', url)) - equals - qmarks - ampersands
    
    features["NoOfLettersInURL"] = letters
    features["LetterRatioInURL"] = letters / len(url) if len(url) > 0 else 0
    features["NoOfDegitsInURL"] = digits  # Note: typo in original, kept as is
    features["DegitRatioInURL"] = digits / len(url) if len(url) > 0 else 0
    features["NoOfEqualsInURL"] = equals
    features["NoOfQMarkInURL"] = qmarks
    features["NoOfAmpersandInURL"] = ampersands
    features["NoOfOtherSpecialCharsInURL"] = specials
    features["SpacialCharRatioInURL"] = (equals + qmarks + ampersands + specials) / len(url) if len(url) > 0 else 0
    
    obfuscated = len(re.findall(r'%[0-9a-fA-F]{2}', url))
    features["HasObfuscation"] = 1 if obfuscated > 0 else 0
    features["NoOfObfuscatedChar"] = obfuscated
    features["ObfuscationRatio"] = obfuscated / len(url) if len(url) > 0 else 0

def fetch_html_features(url: str) -> None:
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        response.raise_for_status()
        
        features["NoOfURLRedirect"] = len(response.history)
        features["NoOfSelfRedirect"] = sum(1 for r in response.history if r.url == url)
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        lines = response.text.splitlines()
        features["LineOfCode"] = len(lines)
        features["LargestLineLength"] = max(len(line) for line in lines) if lines else 0
        
        title_tag = soup.title
        features["HasTitle"] = 1 if title_tag else 0
        features["Title"] = title_tag.string.strip() if title_tag else ""
        
        domain_lower = features["Domain"].lower()
        title_lower = features["Title"].lower()
        url_lower = url.lower()
        features["DomainTitleMatchScore"] = Levenshtein.ratio(domain_lower, title_lower) * 100
        features["URLTitleMatchScore"] = Levenshtein.ratio(url_lower, title_lower) * 100
        
        features["HasFavicon"] = 1 if soup.find('link', rel='shortcut icon') or soup.find('link', rel='icon') else 0
        
        robots_url = urlparse(url)._replace(path='/robots.txt').geturl()
        try:
            robots_resp = requests.get(robots_url, timeout=5)
            features["Robots"] = 1 if robots_resp.status_code == 200 else 0
        except:
            features["Robots"] = 0
        
        features["IsResponsive"] = 1 if soup.find('meta', attrs={'name': 'viewport'}) else 0
        
        features["HasDescription"] = 1 if soup.find('meta', attrs={'name': 'description'}) else 0
        
        scripts = [s.text for s in soup.find_all('script')]
        features["NoOfPopup"] = sum(s.count('window.open') for s in scripts)
        
        features["NoOfiFrame"] = len(soup.find_all('iframe'))
        
        forms = soup.find_all('form')
        features["HasExternalFormSubmit"] = 1 if any(form.get('action', '').startswith('http') and not form.get('action').startswith(url) for form in forms) else 0
        social_patterns = ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com']
        links = [a.get('href') for a in soup.find_all('a')]
        features["HasSocialNet"] = 1 if any(any(p in link for p in social_patterns) for link in links if link) else 0
        features["HasSubmitButton"] = 1 if soup.find('input', attrs={'type': 'submit'}) else 0
        features["HasHiddenFields"] = 1 if soup.find('input', attrs={'type': 'hidden'}) else 0
        features["HasPasswordField"] = 1 if soup.find('input', attrs={'type': 'password'}) else 0
        text = soup.get_text().lower()
        features["Bank"] = 1 if 'bank' in text else 0
        features["Pay"] = 1 if 'pay' in text else 0
        features["Crypto"] = 1 if 'crypto' in text else 0
        features["HasCopyrightInfo"] = 1 if 'copyright' in text else 0
        
        features["NoOfImage"] = len(soup.find_all('img'))
        features["NoOfCSS"] = len(soup.find_all('link', rel='stylesheet'))
        features["NoOfJS"] = len(soup.find_all('script', src=True))
        
        self_refs = sum(1 for link in links if link and urlparse(link).netloc == features["Domain"])
        empty_refs = sum(1 for link in links if not link or link == '#')
        ext_refs = len(links) - self_refs - empty_refs
        features["NoOfSelfRef"] = self_refs
        features["NoOfEmptyRef"] = empty_refs
        features["NoOfExternalRef"] = ext_refs
        
    except Exception as e:
        logging.error(f"Error fetching HTML for {url}: {e}")
        for key in features:
            if isinstance(features[key], int):
                features[key] = -1 if key.startswith('NoOf') or key in ['LineOfCode', 'LargestLineLength'] else 0
            elif isinstance(features[key], float):
                features[key] = 0.0
            elif isinstance(features[key], str):
                features[key] = ""

def advanced_features(url: str) -> None:
    legit_urls = ["https://www.google.com", "https://www.example.com"]  # Add real list
    max_sim = max(Levenshtein.ratio(url, legit) for legit in legit_urls) * 100
    features["URLSimilarityIndex"] = max_sim
    
    consec = sum(1 for i in range(len(url)-1) if url[i] == url[i+1])
    features["CharContinuationRate"] = consec / len(url) if len(url) > 0 else 0
    
    tld_probs = {"com": 0.5229, "org": 0.07996, "de": 0.03265, "uk": 0.02855, "in": 0.00508, "be": 0.00332, "top": 0.000275, "vn": 0.00136, "me": 0.00364, "co": 0.00598, "dev": 0.00096}
    features["TLDLegitimateProb"] = tld_probs.get(features["TLD"], 0.0)
    
    features["URLCharProb"] = sum(ord(c) for c in url) / (len(url) * 122)  # Rough estimate

def parse_string(url: str) -> Dict:
    extract_basic_features(url)
    advanced_features(url)
    fetch_html_features(url)
    return features

