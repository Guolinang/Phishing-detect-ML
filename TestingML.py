#Laaaab\Scripts\Activate.ps1
#pip install -r requirements.txt
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
import parserUrl2
import parserUrl1
import parserUrl4
from sklearn.feature_extraction import DictVectorizer
import warnings
warnings.filterwarnings('ignore')
import logging
logging.basicConfig(level=logging.CRITICAL)
import multiprocessing as mp
from tqdm import tqdm
from functools import partial
from itertools import product

def dict_to_vector2(features):
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

def dict_to_vector1(features):
    ml_vector = [
        features['having_IPhaving_IP_Address'],    # 1. Наличие IP-адреса
        features['URLURL_Length'],                 # 2. Длина URL
        features['Shortining_Service'],            # 3. Использование службы сокращения
        features['having_At_Symbol'],              # 4. Наличие символа '@'
        features['double_slash_redirecting'],      # 5. Двойное перенаправление слэша
        features['Prefix_Suffix'],                 # 6. Использование префикса/суффикса
        features['having_Sub_Domain'],             # 7. Наличие поддомена
        features['SSLfinal_State'],                # 8. Финальное состояние SSL
        features['Domain_registeration_length'],   # 9. Длина регистрации домена
        features['Favicon'],                       # 10. Favicon
        features['port'],                          # 11. Использование порта
        features['HTTPS_token'],                   # 12. Токен HTTPS
        features['Request_URL'],                   # 13. Запрашиваемый URL
        features['URL_of_Anchor'],                 # 14. URL якоря
        features['Links_in_tags'],                 # 15. Ссылки в тегах
        features['SFH'],                           # 16. Server Form Handler (SFH)
        features['Submitting_to_email'],           # 17. Отправка на email
        features['Abnormal_URL'],                  # 18. Аномальный URL
        features['Redirect'],                      # 19. Перенаправление
        features['on_mouseover'],                  # 20. Событие on_mouseover
        features['RightClick'],                    # 21. Правый клик
        features['popUpWidnow'],                   # 22. Всплывающее окно
        features['Iframe'],                        # 23. Iframe
        features['age_of_domain'],                 # 24. Возраст домена
        features['DNSRecord'],                     # 25. Запись DNS
        features['web_traffic'],                   # 26. Веб-трафик
        features['Page_Rank'],                     # 27. Page Rank
        features['Google_Index'],                  # 28. Индексация Google
        features['Links_pointing_to_page'],        # 29. Ссылки, указывающие на страницу
        features['Statistical_report']              # 30. Статистический отчет
    ]
    return ml_vector

def dict_to_vector4(features):
    ml_vector = [
        features["URLLength"],
        features["DomainLength"],
        features["IsDomainIP"],
        features["URLSimilarityIndex"],
        features["CharContinuationRate"],
        features["TLDLegitimateProb"],
        features["URLCharProb"],
        features["TLDLength"],
        features["NoOfSubDomain"],
        features["HasObfuscation"],
        features["NoOfObfuscatedChar"],
        features["ObfuscationRatio"],
        features["NoOfLettersInURL"],
        features["LetterRatioInURL"],
        features["NoOfDegitsInURL"],
        features["DegitRatioInURL"],
        features["NoOfEqualsInURL"],
        features["NoOfQMarkInURL"],
        features["NoOfAmpersandInURL"],
        features["NoOfOtherSpecialCharsInURL"],
        features["SpacialCharRatioInURL"],
        features["IsHTTPS"],
        features["LineOfCode"],
        features["LargestLineLength"],
        features["HasTitle"],
        features["DomainTitleMatchScore"],
        features["URLTitleMatchScore"],
        features["HasFavicon"],
        features["Robots"],
        features["IsResponsive"],
        features["NoOfURLRedirect"],
        features["NoOfSelfRedirect"],
        features["HasDescription"],
        features["NoOfPopup"],
        features["NoOfiFrame"],
        features["HasExternalFormSubmit"],
        features["HasSocialNet"],
        features["HasSubmitButton"],
        features["HasHiddenFields"],
        features["HasPasswordField"],
        features["Bank"],
        features["Pay"],
        features["Crypto"],
        features["HasCopyrightInfo"],
        features["NoOfImage"],
        features["NoOfCSS"],
        features["NoOfJS"],
        features["NoOfSelfRef"],
        features["NoOfEmptyRef"],
        features["NoOfExternalRef"]
    ]
    return ml_vector


import pandas as pd
import joblib
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

PARSER_MAP = {
    '1': parserUrl1,
    '2': parserUrl2,
    '4': parserUrl4
}

DICT_TO_VECTOR_MAP = {
    '1': dict_to_vector1,
    '2': dict_to_vector2,
    '4': dict_to_vector4
}

ALGORITHMS = ['LR', 'KNN', 'NW', 'BC', 'RF']

def load_models():     
    models = {}
    
    for parser_num in ['1', '2', '4']:
        models[parser_num] = {}
        
        for algo in ALGORITHMS:
            model_name = f'model{parser_num}{algo}.joblib'
            models[parser_num][algo] = joblib.load(model_name) 

    return models

def prepare_data(df):
    df_legit = df[df['type'] == 'legitimate'].sample(500, random_state=42)
    df_phish = df[df['type'] == 'phishing'].sample(500, random_state=42)
    df_test = pd.concat([df_legit, df_phish]).reset_index(drop=True)
    
    X_urls = df_test['url'].tolist()
    y_true_text = df_test['type'].tolist()
    
    y_true_1 = np.array([1 if label == 'legitimate' else -1 for label in y_true_text])
    
    y_true_2_4 = np.array([0 if label == 'legitimate' else 1 for label in y_true_text])
    
    return X_urls, {'1': y_true_1, '2': y_true_2_4, '4': y_true_2_4}

def process_task(task, X_urls):
    parser_num, url_idx = task
    url = X_urls[url_idx]
    parser = PARSER_MAP[parser_num]
    dict_to_vector_func = DICT_TO_VECTOR_MAP[parser_num]
    try:
        features = parser.parse_string(url)
        vector = dict_to_vector_func(features)
        return parser_num, url_idx, vector
    except Exception as e:
        print(f"Error processing URL {url} with parser {parser_num}: {e}")
        return parser_num, url_idx, None

def extract_features_and_evaluate(models, X_urls, y_true):
    metrics = {p: {a: {} for a in ALGORITHMS} for p in ['1', '2', '4']}
    
    tasks = list(product(['1', '2', '4'], range(len(X_urls))))
    
    with mp.Pool() as pool:
        results = list(tqdm(pool.imap(partial(process_task, X_urls=X_urls), tasks), total=len(tasks), desc="Processing all parsers"))
    
    vectors_dict = {p: [None] * len(X_urls) for p in ['1', '2', '4']}
    for parser_num, url_idx, vector in results:
        if vector is not None:
            vectors_dict[parser_num][url_idx] = vector
    
    for parser_num in ['1', '2', '4']:
        vectors = vectors_dict[parser_num]
        valid_indices = [i for i, v in enumerate(vectors) if v is not None]
        
        if not valid_indices:
            print(f"No valid vectors for parser {parser_num}")
            continue
        
        X_test = np.array([vectors[i] for i in valid_indices])
        y_true_current = y_true[parser_num][valid_indices]
        
        pos_label = -1 if parser_num == '1' else 1
        
        for algo_name in ALGORITHMS:
            model = models[parser_num][algo_name]
            y_pred = model.predict(X_test)
            
            acc = accuracy_score(y_true_current, y_pred)
            prec = precision_score(y_true_current, y_pred, average='binary', pos_label=pos_label, zero_division=0)
            rec = recall_score(y_true_current, y_pred, average='binary', pos_label=pos_label, zero_division=0)
            f1 = f1_score(y_true_current, y_pred, average='binary', pos_label=pos_label, zero_division=0)
            
            cm = confusion_matrix(y_true_current, y_pred, labels=np.sort(np.unique(y_true_current)))
            
            metrics[parser_num][algo_name] = {
                'accuracy': acc, 'precision': prec, 'recall': rec, 'f1': f1, 'cm': cm
            }
            
            print(f"{parser_num}+{algo_name}: acc: {acc:.4f}, precision: {prec:.4f}, recall: {rec:.4f}, f1: {f1:.4f}")
            
    return metrics

def create_combined_confusion_matrix(metrics):
    parsers = ['1', '2', '4']
    algos = ALGORITHMS
    
    combined_cm_df = pd.DataFrame(index=parsers, columns=algos)
    
    for parser in parsers:
        for algo in algos:
            if 'cm' in metrics[parser][algo]:
                cm_data = metrics[parser][algo]['cm']
                cm_str = str(cm_data).replace('\n', ', ')
                combined_cm_df.loc[parser, algo] = cm_str
            else:
                combined_cm_df.loc[parser, algo] = "N/A"
            
    print("\n\nОбщая Confusion Matrix (CM):")
    print(combined_cm_df)

def plot_accuracy_matrix(metrics):
    parsers = ['1', '2', '4']
    algos = ALGORITHMS
    
    acc_df = pd.DataFrame(index=parsers, columns=algos, dtype=float)
    
    for parser in parsers:
        for algo in algos:
            if 'accuracy' in metrics[parser][algo]:
                acc_df.loc[parser, algo] = metrics[parser][algo]['accuracy']
            else:
                acc_df.loc[parser, algo] = np.nan
    
    plt.figure(figsize=(10, 6))
    sns.heatmap(acc_df, annot=True, fmt=".4f", cmap="YlGnBu", cbar_kws={'label': 'Accuracy'})
    plt.title("Accuracy Matrix: Parsers vs Models")
    plt.xlabel("Models")
    plt.ylabel("Parsers")
    plt.show()

def run_evaluation():
    try:
        df = pd.read_csv('url_dataset.csv')
    except FileNotFoundError:
        data = {
            'url': [f'https://legit.com/{i}' for i in range(500)] + [f'http://phish.net/{i}' for i in range(500)],
            'type': ['legitimate'] * 500 + ['phishing'] * 500
        }
        df = pd.DataFrame(data)

    X_urls, y_true_targets = prepare_data(df)

    models = load_models()

    metrics = extract_features_and_evaluate(models, X_urls, y_true_targets)

    create_combined_confusion_matrix(metrics)
    
    plot_accuracy_matrix(metrics)

if __name__ == '__main__':
    run_evaluation()