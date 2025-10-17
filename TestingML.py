import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
from sklearn.neural_network import MLPClassifier
import parserUrl
from sklearn.feature_extraction import DictVectorizer

def dict_to_vector(features):
    ml_vector = [
    features["url_dot"],                    # qty_dot_url
    features["url_hyphen"],                 # qty_hyphen_url
    features["url_underscore"],             # qty_underline_url
    features["url_slash"],                  # qty_slash_url
    features["url_question"],               # qty_questionmark_url
    features["url_equal"],                  # qty_equal_url
    features["url_at"],                     # qty_at_url
    features["url_ampersand"],              # qty_and_url
    features["url_exclamation"],            # qty_exclamation_url
    features["url_space"],                  # qty_space_url
    features["url_tilde"],                  # qty_tilde_url
    features["url_comma"],                  # qty_comma_url
    features["url_plus"],                   # qty_plus_url
    features["url_asterisk"],               # qty_asterisk_url
    features["url_hash"],                   # qty_hashtag_url
    features["url_dollar"],                 # qty_dollar_url
    features["url_percent"],                # qty_percent_url
    features["qty_tld_url"],                # qty_tld_url
    features["len_url"],                    # length_url
    
    # Domain features
    features["domain_dot"],                 # qty_dot_domain
    features["domain_hyphen"],              # qty_hyphen_domain
    features["domain_underscore"],          # qty_underline_domain
    features["domain_slash"],               # qty_slash_domain
    features["domain_question"],            # qty_questionmark_domain
    features["domain_equal"],               # qty_equal_domain
    features["domain_at"],                  # qty_at_domain
    features["domain_ampersand"],           # qty_and_domain
    features["domain_exclamation"],         # qty_exclamation_domain
    features["domain_space"],               # qty_space_domain
    features["domain_tilde"],               # qty_tilde_domain
    features["domain_comma"],               # qty_comma_domain
    features["domain_plus"],                # qty_plus_domain
    features["domain_asterisk"],            # qty_asterisk_domain
    features["domain_hash"],                # qty_hashtag_domain
    features["domain_dollar"],              # qty_dollar_domain
    features["domain_percent"],             # qty_percent_domain
    features["domain_vowels"],              # qty_vowels_domain
    features["len_domain"],                 # domain_length
    features["domain_in_ip"],               # domain_in_ip
    features["server_client_domain"],       # server_client_domain
    
    # Directory features
    features["directory_dot"],              # qty_dot_directory
    features["directory_hyphen"],           # qty_hyphen_directory
    features["directory_underscore"],       # qty_underline_directory
    features["directory_slash"],            # qty_slash_directory
    features["directory_question"],         # qty_questionmark_directory
    features["directory_equal"],            # qty_equal_directory
    features["directory_at"],               # qty_at_directory
    features["directory_ampersand"],        # qty_and_directory
    features["directory_exclamation"],      # qty_exclamation_directory
    features["directory_space"],            # qty_space_directory
    features["directory_tilde"],            # qty_tilde_directory
    features["directory_comma"],            # qty_comma_directory
    features["directory_plus"],             # qty_plus_directory
    features["directory_asterisk"],         # qty_asterisk_directory
    features["directory_hash"],             # qty_hashtag_directory
    features["directory_dollar"],           # qty_dollar_directory
    features["directory_percent"],          # qty_percent_directory
    features["directory_length"],           # directory_length
    
    # File features
    features["file_dot"],                   # qty_dot_file
    features["file_hyphen"],                # qty_hyphen_file
    features["file_underscore"],            # qty_underline_file
    features["file_slash"],                 # qty_slash_file
    features["file_question"],              # qty_questionmark_file
    features["file_equal"],                 # qty_equal_file
    features["file_at"],                    # qty_at_file
    features["file_ampersand"],             # qty_and_file
    features["file_exclamation"],           # qty_exclamation_file
    features["file_space"],                 # qty_space_file
    features["file_tilde"],                 # qty_tilde_file
    features["file_comma"],                 # qty_comma_file
    features["file_plus"],                  # qty_plus_file
    features["file_asterisk"],              # qty_asterisk_file
    features["file_hash"],                  # qty_hashtag_file
    features["file_dollar"],                # qty_dollar_file
    features["file_percent"],               # qty_percent_file
    features["file_length"],                # file_length
    
    # Parameters features
    features["params_dot"],                 # qty_dot_params
    features["params_hyphen"],              # qty_hyphen_params
    features["params_underscore"],          # qty_underline_params
    features["params_slash"],               # qty_slash_params
    features["params_question"],            # qty_questionmark_params
    features["params_equal"],               # qty_equal_params
    features["params_at"],                  # qty_at_params
    features["params_ampersand"],           # qty_and_params
    features["params_exclamation"],         # qty_exclamation_params
    features["params_space"],               # qty_space_params
    features["params_tilde"],               # qty_tilde_params
    features["params_comma"],               # qty_comma_params
    features["params_plus"],                # qty_plus_params
    features["params_asterisk"],            # qty_asterisk_params
    features["params_hash"],                # qty_hashtag_params
    features["params_dollar"],              # qty_dollar_params
    features["params_percent"],             # qty_percent_params
    features["params_length"],              # params_length
    
    # Other features
    features["email_in_url"],               # email_in_url
    features["time_response"],              # time_response
    features["domain_spf"],                 # domain_spf
    features["asn_ip"],                     # asn_ip
    features["time_domain_activation"],     # time_domain_activation
    features["time_domain_expiration"],     # time_domain_expiration
    features["qty_ip_resolved"],            # qty_ip_resolved
    features["qty_nameservers"],            # qty_nameservers
    features["qty_mx_servers"],             # qty_mx_servers
    features["ttl_hostname"],               # ttl_hostname
    features["tls_ssl_certificate"],        # tls_ssl_certificate
    features["qty_redirects"],              # qty_redirects
    features["url_google_index"],           # url_google_index
    features["domain_google_index"],        # domain_google_index
    features["url_shortened"]               # url_shortened
]
    return ml_vector


model = joblib.load('model.joblib')
url="https://chat.deepseek.com/a/chat/s/423ff76d-4042-4a17-b9bd-a328353c4c44"
feature=parserUrl.parse_string(url)
vector = dict_to_vector(feature)
result = model.predict([vector])
print(f"Результат: {result}")