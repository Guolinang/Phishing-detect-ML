#Laaaab\Scripts\Activate.ps1
#pip install -r requirements.txt
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import joblib
import parserUrl2
import parserUrl1
import parserUrl4
import warnings
warnings.filterwarnings('ignore')

def dict_to_vector2(features):
    ml_vector = [
    features["url_dot"], features["url_hyphen"], features["url_underscore"],
    features["url_slash"], features["url_question"], features["url_equal"],
    features["url_at"], features["url_ampersand"], features["url_exclamation"],
    features["url_space"], features["url_tilde"], features["url_comma"],
    features["url_plus"], features["url_asterisk"], features["url_hash"],
    features["url_dollar"], features["url_percent"], features["qty_tld_url"],
    features["len_url"], features["domain_dot"], features["domain_hyphen"],
    features["domain_underscore"], features["domain_slash"], features["domain_question"],
    features["domain_equal"], features["domain_at"], features["domain_ampersand"],
    features["domain_exclamation"], features["domain_space"], features["domain_tilde"],
    features["domain_comma"], features["domain_plus"], features["domain_asterisk"],
    features["domain_hash"], features["domain_dollar"], features["domain_percent"],
    features["domain_vowels"], features["len_domain"], features["domain_in_ip"],
    features["server_client_domain"], features["directory_dot"], features["directory_hyphen"],
    features["directory_underscore"], features["directory_slash"], features["directory_question"],
    features["directory_equal"], features["directory_at"], features["directory_ampersand"],
    features["directory_exclamation"], features["directory_space"], features["directory_tilde"],
    features["directory_comma"], features["directory_plus"], features["directory_asterisk"],
    features["directory_hash"], features["directory_dollar"], features["directory_percent"],
    features["directory_length"], features["file_dot"], features["file_hyphen"],
    features["file_underscore"], features["file_slash"], features["file_question"],
    features["file_equal"], features["file_at"], features["file_ampersand"],
    features["file_exclamation"], features["file_space"], features["file_tilde"],
    features["file_comma"], features["file_plus"], features["file_asterisk"],
    features["file_hash"], features["file_dollar"], features["file_percent"],
    features["file_length"], features["params_dot"], features["params_hyphen"],
    features["params_underscore"], features["params_slash"], features["params_question"],
    features["params_equal"], features["params_at"], features["params_ampersand"],
    features["params_exclamation"], features["params_space"], features["params_tilde"],
    features["params_comma"], features["params_plus"], features["params_asterisk"],
    features["params_hash"], features["params_dollar"], features["params_percent"],
    features["params_length"], features["email_in_url"], features["time_response"],
    features["domain_spf"], features["asn_ip"], features["time_domain_activation"],
    features["time_domain_expiration"], features["qty_ip_resolved"], features["qty_nameservers"],
    features["qty_mx_servers"], features["ttl_hostname"], features["tls_ssl_certificate"],
    features["qty_redirects"], features["url_google_index"], features["domain_google_index"],
    features["url_shortened"]
    ]
    return ml_vector

def dict_to_vector1(features):
    ml_vector = [
        features['having_IPhaving_IP_Address'], features['URLURL_Length'],
        features['Shortining_Service'], features['having_At_Symbol'],
        features['double_slash_redirecting'], features['Prefix_Suffix'],
        features['having_Sub_Domain'], features['SSLfinal_State'],
        features['Domain_registeration_length'], features['Favicon'],
        features['port'], features['HTTPS_token'], features['Request_URL'],
        features['URL_of_Anchor'], features['Links_in_tags'], features['SFH'],
        features['Submitting_to_email'], features['Abnormal_URL'],
        features['Redirect'], features['on_mouseover'], features['RightClick'],
        features['popUpWidnow'], features['Iframe'], features['age_of_domain'],
        features['DNSRecord'], features['web_traffic'], features['Page_Rank'],
        features['Google_Index'], features['Links_pointing_to_page'],
        features['Statistical_report']
    ]
    return ml_vector

def dict_to_vector4(features):
    ml_vector = [
        features["URLLength"], features["DomainLength"], features["IsDomainIP"],
        features["URLSimilarityIndex"], features["CharContinuationRate"],
        features["TLDLegitimateProb"], features["URLCharProb"], features["TLDLength"],
        features["NoOfSubDomain"], features["HasObfuscation"],
        features["NoOfObfuscatedChar"], features["ObfuscationRatio"],
        features["NoOfLettersInURL"], features["LetterRatioInURL"],
        features["NoOfDegitsInURL"], features["DegitRatioInURL"],
        features["NoOfEqualsInURL"], features["NoOfQMarkInURL"],
        features["NoOfAmpersandInURL"], features["NoOfOtherSpecialCharsInURL"],
        features["SpacialCharRatioInURL"], features["IsHTTPS"],
        features["LineOfCode"], features["LargestLineLength"], features["HasTitle"],
        features["DomainTitleMatchScore"], features["URLTitleMatchScore"],
        features["HasFavicon"], features["Robots"], features["IsResponsive"],
        features["NoOfURLRedirect"], features["NoOfSelfRedirect"],
        features["HasDescription"], features["NoOfPopup"], features["NoOfiFrame"],
        features["HasExternalFormSubmit"], features["HasSocialNet"],
        features["HasSubmitButton"], features["HasHiddenFields"],
        features["HasPasswordField"], features["Bank"], features["Pay"],
        features["Crypto"], features["HasCopyrightInfo"], features["NoOfImage"],
        features["NoOfCSS"], features["NoOfJS"], features["NoOfSelfRef"],
        features["NoOfEmptyRef"], features["NoOfExternalRef"]
    ]
    return ml_vector

def get_test_urls(legitimate_count=10, phishing_count=10):
    """Берем тестовые URL из top-1m.csv + фишинговые сайты"""
    legitimate_urls = []
    
    print("📥 Загрузка легитимных URL из top-1m.csv...")
    try:
        with open('top-1m.csv', 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                if i >= legitimate_count:
                    break
                rank, domain = line.strip().split(',')
                legitimate_urls.append(f"https://{domain}")
        print(f"✅ Загружено {len(legitimate_urls)} легитимных URL")
    except Exception as e:
        print(f"❌ Ошибка загрузки top-1m.csv: {e}")
        legitimate_urls = [
            "https://google.com", "https://youtube.com", "https://facebook.com",
            "https://wikipedia.org", "https://twitter.com", "https://instagram.com",
            "https://linkedin.com", "https://microsoft.com", "https://apple.com",
            "https://amazon.com"
        ]
    
    phishing_urls = [
        "https://freeflow25.myshopify.com/", "http://110.37.6.176:36069/i",
        "http://moonpay-login.my.canva.site", "https://bandbsmengine.com",
        "http://mass.gov-xgz.bond/rmv", "http://365internacional.webcindario.com/",
        "http://123.190.191.43:45555/i", "http://zonemaxs.vip",
        "http://64.112.42.225:83/xmrig", "https://fifiyiy.com/"
    ]
    
    print(f"✅ Используется {len(phishing_urls[:phishing_count])} фишинговых URL")
    return {'legitimate': legitimate_urls, 'phishing': phishing_urls[:phishing_count]}

def load_all_models():
    """Загрузка всех моделей для всех парсеров"""
    models = {}
    
    print("\n📦 ЗАГРУЗКА МОДЕЛЕЙ:")
    print("="*40)
    
    # Модели для парсера 1 (dataset1)
    parser1_models = ['BC', 'KNN', 'LR', 'NW', 'RF']
    models['parser1'] = {}
    for algo in parser1_models:
        try:
            model_name = f'model1{algo}.joblib'
            models['parser1'][algo] = joblib.load(model_name)
            print(f"✓ Загружена: Парсер1+{algo}")
        except Exception as e:
            print(f"✗ Ошибка загрузки Парсер1+{algo}: {e}")
    
    # Модели для парсера 2 (dataset2)
    parser2_models = ['BC', 'KNN', 'LR', 'NW', 'RF']
    models['parser2'] = {}
    for algo in parser2_models:
        try:
            model_name = f'model2{algo}.joblib'
            models['parser2'][algo] = joblib.load(model_name)
            print(f"✓ Загружена: Парсер2+{algo}")
        except Exception as e:
            print(f"✗ Ошибка загрузки Парсер2+{algo}: {e}")
    
    # Модели для парсера 4 (dataset4)
    parser4_models = ['BC', 'KNN', 'LR', 'NW', 'RF']
    models['parser4'] = {}
    for algo in parser4_models:
        try:
            model_name = f'model4{algo}.joblib'
            models['parser4'][algo] = joblib.load(model_name)
            print(f"✓ Загружена: Парсер4+{algo}")
        except Exception as e:
            print(f"✗ Ошибка загрузки Парсер4+{algo}: {e}")
    
    print(f"✅ Всего загружено моделей: "
          f"{len(models['parser1'])+len(models['parser2'])+len(models['parser4'])}/15")
    return models

def test_url_with_all_models(url, url_type, models):
    """Тестирование одного URL всеми моделями"""
    results = []
    
    # Получаем признаки от всех парсеров
    try:
        features1 = parserUrl1.parse_string(url)
        features2 = parserUrl2.parse_string(url)
        features4 = parserUrl4.parse_string(url)
    except Exception as e:
        print(f"    ⚠️ Ошибка парсера для {url}: {e}")
        return results
    
    # Определяем ожидаемую метку
    expected_label = 0 if url_type == 'legitimate' else 1
    
    # Тестируем все комбинации парсер+модель
    for parser_name, algorithm_models in models.items():
        for algo, model in algorithm_models.items():
            try:
                # Выбираем правильный вектор в зависимости от парсера
                if parser_name == 'parser1':
                    vector = dict_to_vector1(features1)
                    # ЗАГРУЖАЕМ SCALER
                    scaler_name = f'scaler1{algo}.joblib'
                    try:
                        scaler = joblib.load(scaler_name)
                        
                        # Создаем DataFrame с ПРАВИЛЬНЫМИ именами признаков (ровно 30)
                        feature_names = [
                            'having_IPhaving_IP_Address', 'URLURL_Length', 'Shortining_Service',
                            'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
                            'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length',
                            'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor',
                            'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
                            'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe',
                            'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank',
                            'Google_Index', 'Links_pointing_to_page', 'Statistical_report'
                        ]
                        
                        # Проверяем размерности
                        if len(vector) != 30:
                            print(f"    ⚠️ Внимание: вектор имеет {len(vector)} признаков, ожидается 30")
                        
                        df_vector = pd.DataFrame([vector], columns=feature_names)
                        
                        # Масштабируем - передаем DataFrame, а не список!
                        vector_scaled = scaler.transform(df_vector)
                        prediction = model.predict(vector_scaled)[0]
 
                    except Exception as e:
                        # Если scaler не найден, используем без масштабирования
                        prediction = model.predict([vector])[0]
                elif parser_name == 'parser2':
                    vector = dict_to_vector2(features2)
                    prediction = model.predict([vector])[0]
                else:  # parser4
                    vector = dict_to_vector4(features4)
                    prediction = model.predict([vector])[0]
                
                # Предсказание
                #prediction = model.predict([vector])[0]
                
                # Для парсера1 преобразуем -1,0,1 в 0,1
                if parser_name == 'parser1':
                    if prediction == -1:
                        prediction_binary = 1  # фишинг
                        prediction_label = 'ФИШИНГ'
                    elif prediction == 0:
                        prediction_binary = 0  # подозрительный
                        prediction_label = 'ПОДОЗРИТЕЛЬНЫЙ'
                    else:
                        prediction_binary = 0  # легитимный
                        prediction_label = 'ЛЕГИТИМНЫЙ'
                else:
                    prediction_binary = prediction
                    prediction_label = 'ФИШИНГ' if prediction == 1 else 'ЛЕГИТИМНЫЙ'
                
                # Проверяем правильность предсказания
                is_correct = (prediction_binary == expected_label)
                
                results.append({
                    'url': url,
                    'type': url_type,
                    'parser': parser_name,
                    'algorithm': algo,
                    'prediction': prediction,
                    'prediction_binary': prediction_binary,
                    'prediction_label': prediction_label,
                    'expected': expected_label,
                    'correct': is_correct,
                    'error_type': 'Ложное срабатывание' if (url_type == 'legitimate' and prediction_binary == 1) 
                    else 'Пропущенная угроза' if (url_type == 'phishing' and prediction_binary == 0) else 'Все хорошо'
                })
                
            except Exception as e:
                print(f"    ⚠️ Ошибка {parser_name}+{algo} для {url}: {e}")
    
    return results

def create_detailed_analysis(all_results):
    """Создание детального анализа для каждой комбинации"""
    df = pd.DataFrame(all_results)
    
    detailed_results = []
    
    # Для каждой комбинации парсер+алгоритм
    for parser in ['parser1', 'parser2', 'parser4']:
        for algo in ['BC', 'KNN', 'LR', 'NW', 'RF']:
            combo_data = df[(df['parser'] == parser) & (df['algorithm'] == algo)]
            
            if len(combo_data) > 0:
                # Считаем статистику
                total_tests = len(combo_data)
                correct_predictions = combo_data['correct'].sum()
                accuracy = correct_predictions / total_tests if total_tests > 0 else 0
                
                # Распределение предсказаний
                legit_as_legit = len(combo_data[(combo_data['type'] == 'legitimate') & (combo_data['prediction_binary'] == 0)])
                legit_as_phishing = len(combo_data[(combo_data['type'] == 'legitimate') & (combo_data['prediction_binary'] == 1)])
                phishing_as_phishing = len(combo_data[(combo_data['type'] == 'phishing') & (combo_data['prediction_binary'] == 1)])
                phishing_as_legit = len(combo_data[(combo_data['type'] == 'phishing') & (combo_data['prediction_binary'] == 0)])
                
                detailed_results.append({
                    'parser': parser,
                    'algorithm': algo,
                    'total_tests': total_tests,
                    'accuracy': accuracy,
                    'legit_as_legit': legit_as_legit,
                    'legit_as_phishing': legit_as_phishing,
                    'phishing_as_phishing': phishing_as_phishing,
                    'phishing_as_legit': phishing_as_legit,
                    'false_positives': legit_as_phishing,
                    'false_negatives': phishing_as_legit
                })
    
    return pd.DataFrame(detailed_results)

def show_all_classifications(all_results):
    """Показать классификацию всех сайтов"""
    df = pd.DataFrame(all_results)
    
    print("\n" + "="*80)
    print("📋 КЛАССИФИКАЦИЯ ВСЕХ САЙТОВ")
    print("="*80)
    
    # Группируем по URL
    unique_urls = df['url'].unique()
    
    for i, url in enumerate(unique_urls):
        url_data = df[df['url'] == url]
        url_type = url_data.iloc[0]['type']
        
        print(f"\n{'='*60}")
        print(f"{i+1}. {url}")
        print(f"   Тип: {'ЛЕГИТИМНЫЙ' if url_type == 'legitimate' else 'ФИШИНГОВЫЙ'}")
        print(f"{'-'*60}")
        
        # Группируем по комбинациям
        for parser in ['parser1', 'parser2', 'parser4']:
            for algo in ['BC', 'KNN', 'LR', 'NW', 'RF']:
                combo_data = url_data[(url_data['parser'] == parser) & (url_data['algorithm'] == algo)]
                
                if len(combo_data) > 0:
                    row = combo_data.iloc[0]
                    status = "✅" if row['correct'] else "❌"
                    print(f"   {status} {parser}+{algo}: {row['prediction_label']}")

def analyze_results(all_results):
    """Анализ и отображение результатов"""
    df = pd.DataFrame(all_results)
    
    if len(df) == 0:
        print("❌ Нет результатов для анализа")
        return None
    
    print("\n" + "="*60)
    print("📊 АНАЛИТИКА РЕЗУЛЬТАТОВ")
    print("="*60)
    
    # Общая статистика
    total_tests = len(df)
    correct_predictions = df['correct'].sum()
    overall_accuracy = correct_predictions / total_tests
    
    print(f"\n📈 ОБЩАЯ СТАТИСТИКА:")
    print(f"   Всего тестов: {total_tests}")
    print(f"   Правильных предсказаний: {correct_predictions}")
    print(f"   Общая точность: {overall_accuracy:.1%}")
    
    # Статистика по типам ошибок
    false_positives = len(df[(df['type'] == 'legitimate') & (df['prediction_binary'] == 1)])
    false_negatives = len(df[(df['type'] == 'phishing') & (df['prediction_binary'] == 0)])
    
    print(f"\n⚠️  ОШИБКИ КЛАССИФИКАЦИИ:")
    print(f"   Ложные срабатывания (легитимные → фишинг): {false_positives}")
    print(f"   Пропущенные угрозы (фишинг → легитимные): {false_negatives}")
    
    # Статистика по парсерам
    print(f"\n📊 СТАТИСТИКА ПО ПАРСЕРАМ:")
    for parser in ['parser1', 'parser2', 'parser4']:
        parser_data = df[df['parser'] == parser]
        if len(parser_data) > 0:
            parser_correct = parser_data['correct'].sum()
            parser_accuracy = parser_correct / len(parser_data)
            print(f"   {parser}: точность {parser_accuracy:.1%} ({parser_correct}/{len(parser_data)})")
    
    # Статистика по алгоритмам
    print(f"\n📊 СТАТИСТИКА ПО АЛГОРИТМАМ:")
    algorithms = ['BC', 'KNN', 'LR', 'NW', 'RF']
    for algo in algorithms:
        algo_data = df[df['algorithm'] == algo]
        if len(algo_data) > 0:
            algo_correct = algo_data['correct'].sum()
            algo_accuracy = algo_correct / len(algo_data)
            print(f"   {algo}: точность {algo_accuracy:.1%} ({algo_correct}/{len(algo_data)})")
    
    # Детальные результаты для каждой комбинации
    print(f"\n🔍 РЕЗУЛЬТАТЫ ПО КОМБИНАЦИЯМ ПАРСЕР+МОДЕЛЬ:")
    print("-"*70)
    
    detailed_df = create_detailed_analysis(all_results)
    
    for _, row in detailed_df.iterrows():
        print(f"  {row['parser']}+{row['algorithm']}:")
        print(f"    Точность: {row['accuracy']:.1%} ({int(row['accuracy']*row['total_tests'])}/{row['total_tests']})")
        print(f"    Лег→Лег: {row['legit_as_legit']}, Лег→Фиш: {row['legit_as_phishing']}")
        print(f"    Фиш→Фиш: {row['phishing_as_phishing']}, Фиш→Лег: {row['phishing_as_legit']}")
        print(f"    Ложные срабатывания: {row['false_positives']}, Пропущенные угрозы: {row['false_negatives']}")
    
    # Показать все классификации
    show_all_classifications(all_results)
    
    # Сохранение результатов
    df.to_csv('phishing_detection_results.csv', index=False, encoding='utf-8')
    detailed_df.to_csv('detailed_analysis_results.csv', index=False, encoding='utf-8')
    print(f"\n💾 Результаты сохранены:")
    print(f"   - phishing_detection_results.csv")
    print(f"   - detailed_analysis_results.csv")
    
    return df, detailed_df

def create_confusion_matrix_chart(detailed_df):
    """График Confusion Matrix для всех комбинаций"""
    fig, axes = plt.subplots(3, 5, figsize=(20, 12))
    axes = axes.flatten()
    
    # Создаем список всех комбинаций
    model_combinations = []
    for parser in ['parser1', 'parser2', 'parser4']:
        for algo in ['BC', 'KNN', 'LR', 'NW', 'RF']:
            model_combinations.append((parser, algo))
    
    for idx, (parser, algorithm) in enumerate(model_combinations):
        if idx >= len(axes):
            break
            
        ax = axes[idx]
        
        # Находим данные для этой комбинации
        combo_data = detailed_df[(detailed_df['parser'] == parser) & 
                                (detailed_df['algorithm'] == algorithm)]
        
        if len(combo_data) > 0:
            model_data = combo_data.iloc[0]
            
            # Создаем confusion matrix
            cm = np.array([
                [model_data['legit_as_legit'], model_data['legit_as_phishing']],
                [model_data['phishing_as_legit'], model_data['phishing_as_phishing']]
            ])
            
            # Нормализуем для цветовой карты
            cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
            cm_normalized = np.nan_to_num(cm_normalized)
            
            # Отображаем confusion matrix
            im = ax.imshow(cm_normalized, interpolation='nearest', cmap=plt.cm.Blues, vmin=0, vmax=1)
            
            # Добавляем текст
            thresh = cm_normalized.max() / 2.
            for i in range(2):
                for j in range(2):
                    # Абсолютные значения
                    ax.text(j, i, f'{cm[i, j]}',
                           horizontalalignment="center",
                           color="white" if cm_normalized[i, j] > thresh else "black",
                           fontweight='bold', fontsize=12)
                    # Проценты (мелким шрифтом)
                    ax.text(j, i+0.3, f'({cm_normalized[i, j]:.1%})',
                           horizontalalignment="center",
                           color="white" if cm_normalized[i, j] > thresh else "black",
                           fontsize=9)
            
            ax.set_title(f'{parser}+{algorithm}\nAccuracy: {model_data["accuracy"]:.1%}', 
                        fontweight='bold', fontsize=10)
            
            # Подписи осей
            ax.set_xticks([0, 1])
            ax.set_yticks([0, 1])
            ax.set_xticklabels(['Legit', 'Phish'], fontsize=9)
            ax.set_yticklabels(['Legit', 'Phish'], fontsize=9)
            
            # Убираем лишние линии
            ax.set_xlabel('Predicted', fontsize=9)
            ax.set_ylabel('Actual', fontsize=9)
            
            # Добавляем цветовую шкалу только для первого графика
            if idx == 0:
                plt.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
            
        else:
            ax.set_title(f'{parser}+{algorithm}\nНет данных', fontweight='bold', fontsize=10)
            ax.text(0.5, 0.5, 'Нет данных', ha='center', va='center', transform=ax.transAxes)
    
    # Скрываем пустые subplots
    for idx in range(len(model_combinations), len(axes)):
        axes[idx].set_visible(False)
    
    plt.suptitle('Confusion Matrix для всех комбинаций парсер+модель', 
                fontweight='bold', fontsize=16, y=1.02)
    plt.tight_layout()
    plt.savefig('confusion_matrices.png', dpi=300, bbox_inches='tight', facecolor='white')
    plt.show()
    print("📊 Confusion Matrix сохранена как 'confusion_matrices.png'")

def create_visualization(df, detailed_df):
    """Создание визуализации результатов"""
    try:
        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        
        # 1. Точность по парсерам
        parser_acc = df.groupby('parser')['correct'].mean()
        axes[0, 0].bar(parser_acc.index, parser_acc.values, color=['skyblue', 'lightgreen', 'lightcoral'])
        axes[0, 0].set_title('Точность по парсерам', fontweight='bold')
        axes[0, 0].set_ylim(0, 1)
        for i, acc in enumerate(parser_acc.values):
            axes[0, 0].text(i, acc + 0.02, f'{acc:.1%}', ha='center', fontweight='bold')
        
        # 2. Точность по алгоритмам
        algo_acc = df.groupby('algorithm')['correct'].mean()
        axes[0, 1].bar(algo_acc.index, algo_acc.values, color='lightblue')
        axes[0, 1].set_title('Точность по алгоритмам', fontweight='bold')
        axes[0, 1].set_ylim(0, 1)
        for i, acc in enumerate(algo_acc.values):
            axes[0, 1].text(i, acc + 0.02, f'{acc:.1%}', ha='center', fontweight='bold')
        
        # 3. Ошибки по типам
        error_counts = df['error_type'].value_counts()
        if not error_counts.empty:
            axes[1, 0].bar(error_counts.index, error_counts.values, color=['orange', 'red'])
            axes[1, 0].set_title('Типы ошибок', fontweight='bold')
            for i, count in enumerate(error_counts.values):
                axes[1, 0].text(i, count + 0.5, f'{count}', ha='center', fontweight='bold')
        
        # 4. Матрица точности по комбинациям
        combo_acc = df.groupby(['parser', 'algorithm'])['correct'].mean().unstack()
        im = axes[1, 1].imshow(combo_acc.values, cmap='RdYlGn', vmin=0, vmax=1)
        axes[1, 1].set_title('Точность по комбинациям', fontweight='bold')
        axes[1, 1].set_xticks(range(len(combo_acc.columns)))
        axes[1, 1].set_xticklabels(combo_acc.columns)
        axes[1, 1].set_yticks(range(len(combo_acc.index)))
        axes[1, 1].set_yticklabels(combo_acc.index)
        
        # Добавляем значения в ячейки
        for i in range(len(combo_acc.index)):
            for j in range(len(combo_acc.columns)):
                axes[1, 1].text(j, i, f'{combo_acc.iloc[i, j]:.1%}', 
                              ha='center', va='center', color='black', fontweight='bold')
        
        plt.colorbar(im, ax=axes[1, 1])
        plt.tight_layout()
        plt.savefig('phishing_detection_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        print("📊 Визуализация сохранена как 'phishing_detection_analysis.png'")
        
        # Создаем график распределения предсказаний
        create_confusion_matrix_chart(detailed_df)
        create_summary_confusion_matrix(detailed_df)
        
        
    except Exception as e:
        print(f"⚠️ Ошибка при создании визуализации: {e}")
        
def create_summary_confusion_matrix(detailed_df):
    """Сводная Confusion Matrix для всех моделей по парсерам"""
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))
    
    for idx, parser in enumerate(['parser1', 'parser2', 'parser4']):
        ax = axes[idx]
        
        # Суммируем результаты по всем алгоритмам для этого парсера
        parser_data = detailed_df[detailed_df['parser'] == parser]
        
        if len(parser_data) > 0:
            # Суммируем все значения
            total_legit_as_legit = parser_data['legit_as_legit'].sum()
            total_legit_as_phishing = parser_data['legit_as_phishing'].sum()
            total_phishing_as_phishing = parser_data['phishing_as_phishing'].sum()
            total_phishing_as_legit = parser_data['phishing_as_legit'].sum()
            
            # Создаем confusion matrix
            cm = np.array([
                [total_legit_as_legit, total_legit_as_phishing],
                [total_phishing_as_legit, total_phishing_as_phishing]
            ])
            
            # Рассчитываем метрики
            total_correct = total_legit_as_legit + total_phishing_as_phishing
            total = cm.sum()
            accuracy = total_correct / total if total > 0 else 0
            
            # Precision, Recall, F1 для класса "фишинг"
            precision = total_phishing_as_phishing / (total_phishing_as_phishing + total_legit_as_phishing) if (total_phishing_as_phishing + total_legit_as_phishing) > 0 else 0
            recall = total_phishing_as_phishing / (total_phishing_as_phishing + total_phishing_as_legit) if (total_phishing_as_phishing + total_phishing_as_legit) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            # Нормализуем
            cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
            cm_normalized = np.nan_to_num(cm_normalized)
            
            # Отображаем
            im = ax.imshow(cm_normalized, interpolation='nearest', cmap=plt.cm.Blues, vmin=0, vmax=1)
            
            # Добавляем текст
            thresh = cm_normalized.max() / 2.
            for i in range(2):
                for j in range(2):
                    ax.text(j, i, f'{cm[i, j]}',
                           horizontalalignment="center",
                           color="white" if cm_normalized[i, j] > thresh else "black",
                           fontweight='bold', fontsize=14)
                    ax.text(j, i+0.3, f'({cm_normalized[i, j]:.1%})',
                           horizontalalignment="center",
                           color="white" if cm_normalized[i, j] > thresh else "black",
                           fontsize=11)
            
            # Метрики в заголовке
            ax.set_title(f'{parser}\nAccuracy: {accuracy:.1%} | F1: {f1:.1%}', 
                        fontweight='bold', fontsize=12)
            
            ax.set_xticks([0, 1])
            ax.set_yticks([0, 1])
            ax.set_xticklabels(['Legit', 'Phish'], fontsize=11)
            ax.set_yticklabels(['Legit', 'Phish'], fontsize=11)
            ax.set_xlabel('Predicted', fontsize=11)
            ax.set_ylabel('Actual', fontsize=11)
            
            # Добавляем сетку
            ax.grid(False)
            
        else:
            ax.set_title(f'{parser}\nНет данных', fontweight='bold', fontsize=12)
            ax.text(0.5, 0.5, 'Нет данных', ha='center', va='center', transform=ax.transAxes)
    
    plt.colorbar(im, ax=axes.ravel().tolist(), fraction=0.046, pad=0.04)
    plt.suptitle('Сводные Confusion Matrix по парсерам', fontweight='bold', fontsize=16)
    plt.tight_layout()
    plt.savefig('summary_confusion_matrices.png', dpi=300, bbox_inches='tight')
    plt.show()
    print("📊 Сводные Confusion Matrix сохранены как 'summary_confusion_matrices.png'")  

def create_model_performance_chart(detailed_df):
    """График производительности всех комбинаций Парсер + Модель"""
    plt.figure(figsize=(15, 10))
    
    # Создаем комбинированные метки
    detailed_df['model_combo'] = detailed_df['parser'] + ' + ' + detailed_df['algorithm']
    
    # Сортируем по точности
    df_sorted = detailed_df.sort_values('accuracy', ascending=True)
    
    # Создаем цветовую схему по парсерам
    parser_colors = {
        'parser1': 'skyblue',
        'parser2': 'lightgreen', 
        'parser4': 'lightcoral'
    }
    
    colors = [parser_colors.get(combo.split(' + ')[0], 'gray') for combo in df_sorted['model_combo']]
    
    # Создаем график
    bars = plt.barh(range(len(df_sorted)), df_sorted['accuracy'], color=colors, alpha=0.8, edgecolor='black')
    
    plt.title('Точность всех комбинаций Парсер + Модель', fontweight='bold', pad=20, fontsize=16)
    plt.xlabel('Точность', fontweight='bold', fontsize=12)
    plt.ylabel('Комбинация моделей', fontweight='bold', fontsize=12)
    plt.yticks(range(len(df_sorted)), df_sorted['model_combo'], fontsize=10)
    plt.xlim(0, 1.05)
    
    # Добавляем значения на столбцы
    for i, (bar, accuracy) in enumerate(zip(bars, df_sorted['accuracy'])):
        plt.text(bar.get_width() + 0.01, bar.get_y() + bar.get_height()/2, 
                f'{accuracy:.1%}', ha='left', va='center', fontweight='bold', fontsize=10)
        
        # Добавляем количество тестов
        total_tests = df_sorted.iloc[i]['total_tests']
        correct = int(accuracy * total_tests)
        plt.text(bar.get_width() + 0.01, bar.get_y() + bar.get_height()/2 - 0.15, 
                f'({correct}/{total_tests})', ha='left', va='center', fontsize=9, alpha=0.8)
    
    # Добавляем легенду для парсеров
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='skyblue', alpha=0.8, edgecolor='black', label='Parser1'),
        Patch(facecolor='lightgreen', alpha=0.8, edgecolor='black', label='Parser2'),
        Patch(facecolor='lightcoral', alpha=0.8, edgecolor='black', label='Parser4')
    ]
    plt.legend(handles=legend_elements, loc='lower right', fontsize=10)
    
    # Добавляем сетку
    plt.grid(axis='x', alpha=0.3, linestyle='--')
    
    # Добавляем горизонтальные линии для разделения
    for i in range(len(df_sorted)-1):
        plt.axhline(i + 0.5, color='gray', linestyle=':', alpha=0.3, linewidth=0.5)
    
    plt.tight_layout()
    plt.savefig('model_combination_accuracy.png', dpi=300, bbox_inches='tight', facecolor='white')
    plt.show()
    print("📊 График точности комбинаций сохранен как 'model_combination_accuracy.png'")

def create_error_analysis_chart(detailed_df):
    """График анализа ошибок по комбинациям"""
    fig, axes = plt.subplots(1, 2, figsize=(16, 8))
    
    # График 1: Ложные срабатывания (False Positives)
    # Группируем и сортируем
    detailed_df['combo'] = detailed_df['parser'] + '+' + detailed_df['algorithm']
    df_sorted_fp = detailed_df.sort_values('false_positives', ascending=True)
    
    colors_fp = ['orange' if x > 0 else 'lightgray' for x in df_sorted_fp['false_positives']]
    
    bars1 = axes[0].barh(range(len(df_sorted_fp)), df_sorted_fp['false_positives'], 
                        color=colors_fp, alpha=0.8, edgecolor='black')
    axes[0].set_title('Ложные срабатывания (Легитимные → Фишинг)', fontweight='bold', fontsize=14, pad=15)
    axes[0].set_xlabel('Количество ложных срабатываний', fontweight='bold', fontsize=11)
    axes[0].set_yticks(range(len(df_sorted_fp)))
    axes[0].set_yticklabels([f"{row['parser']}\n{row['algorithm']}" for _, row in df_sorted_fp.iterrows()], 
                           fontsize=10)
    
    # Добавляем значения на столбцы
    for bar, value in zip(bars1, df_sorted_fp['false_positives']):
        if value > 0:
            axes[0].text(bar.get_width() + 0.05, bar.get_y() + bar.get_height()/2, 
                        f'{value}', ha='left', va='center', fontweight='bold', fontsize=10)
    
    # График 2: Пропущенные угрозы (False Negatives)
    df_sorted_fn = detailed_df.sort_values('false_negatives', ascending=True)
    colors_fn = ['red' if x > 0 else 'lightgray' for x in df_sorted_fn['false_negatives']]
    
    bars2 = axes[1].barh(range(len(df_sorted_fn)), df_sorted_fn['false_negatives'], 
                        color=colors_fn, alpha=0.8, edgecolor='black')
    axes[1].set_title('Пропущенные угрозы (Фишинг → Легитимные)', fontweight='bold', fontsize=14, pad=15)
    axes[1].set_xlabel('Количество пропущенных угроз', fontweight='bold', fontsize=11)
    axes[1].set_yticks(range(len(df_sorted_fn)))
    axes[1].set_yticklabels([f"{row['parser']}\n{row['algorithm']}" for _, row in df_sorted_fn.iterrows()], 
                           fontsize=10)
    
    # Добавляем значения на столбцы
    for bar, value in zip(bars2, df_sorted_fn['false_negatives']):
        if value > 0:
            axes[1].text(bar.get_width() + 0.05, bar.get_y() + bar.get_height()/2, 
                        f'{value}', ha='left', va='center', fontweight='bold', fontsize=10)
    
    # Добавляем общие настройки
    for ax in axes:
        ax.grid(axis='x', alpha=0.3, linestyle='--')
        ax.set_xlim(0, max(max(detailed_df['false_positives'].max(), 
                              detailed_df['false_negatives'].max()) * 1.2, 1))
        # Добавляем горизонтальные линии
        for i in range(len(df_sorted_fp)-1):
            ax.axhline(i + 0.5, color='gray', linestyle=':', alpha=0.3, linewidth=0.5)
    
    plt.suptitle('Анализ ошибок классификации по комбинациям моделей', 
                fontweight='bold', fontsize=16, y=1.02)
    plt.tight_layout()
    plt.savefig('model_error_analysis.png', dpi=300, bbox_inches='tight', facecolor='white')
    plt.show()
    print("📊 График анализа ошибок сохранен как 'model_error_analysis.png'")

def create_prediction_distribution_chart(detailed_df):
    """График распределения предсказаний по всем комбинациям (адаптированная версия)"""
    fig, axes = plt.subplots(3, 5, figsize=(20, 12))
    axes = axes.flatten()
    
    # Создаем список всех комбинаций в правильном порядке
    model_combinations = []
    for parser in ['parser1', 'parser2', 'parser4']:
        for algo in ['BC', 'KNN', 'LR', 'NW', 'RF']:
            model_combinations.append((parser, algo))
    
    for idx, (parser, algorithm) in enumerate(model_combinations):
        if idx >= len(axes):
            break
            
        ax = axes[idx]
        
        # Находим данные для этой комбинации
        combo_data = detailed_df[(detailed_df['parser'] == parser) & 
                                (detailed_df['algorithm'] == algorithm)]
        
        if len(combo_data) > 0:
            model_data = combo_data.iloc[0]
            
            categories = ['Лег→Лег', 'Лег→Фиш', 'Фиш→Фиш', 'Фиш→Лег']
            values = [
                model_data['legit_as_legit'],
                model_data['legit_as_phishing'],
                model_data['phishing_as_phishing'], 
                model_data['phishing_as_legit']
            ]
            
            # Цвета в зависимости от типа парсера
            if parser == 'parser1':
                colors = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728']  # яркие цвета
            elif parser == 'parser2':
                colors = ['#aec7e8', '#ffbb78', '#98df8a', '#ff9896']  # пастельные
            else:  # parser4
                colors = ['#7b9eb0', '#e79f7b', '#7bc07b', '#e77b7b']  # приглушенные
            
            bars = ax.bar(categories, values, color=colors, alpha=0.8, edgecolor='black')
            
            # Расчет дополнительных метрик
            total = sum(values)
            accuracy = (values[0] + values[2]) / total if total > 0 else 0
            precision = values[2] / (values[2] + values[1]) if (values[2] + values[1]) > 0 else 0
            recall = values[2] / (values[2] + values[3]) if (values[2] + values[3]) > 0 else 0
            
            ax.set_title(f'{parser}+{algorithm}\nAcc: {accuracy:.1%}', 
                        fontweight='bold', fontsize=11)
            ax.tick_params(axis='x', rotation=45, labelsize=9)
            ax.tick_params(axis='y', labelsize=9)
            
            # Добавляем значения на столбцы
            for bar, value in zip(bars, values):
                if value > 0:
                    ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                           f'{value}', ha='center', va='bottom', fontsize=8, fontweight='bold')
            
            # Устанавливаем одинаковые лимиты для сравнения
            max_value = max(values) if values else 10
            ax.set_ylim(0, max_value * 1.25)
            
            # Добавляем сетку
            ax.grid(axis='y', alpha=0.3, linestyle='--')
            
            # Добавляем метрики под графиком
            ax.text(0.5, -0.25, f'Precision: {precision:.1%} | Recall: {recall:.1%}', 
                   ha='center', va='center', transform=ax.transAxes, fontsize=8)
            
        else:
            ax.set_title(f'{parser}+{algorithm}\nНет данных', fontweight='bold', fontsize=11)
            ax.text(0.5, 0.5, 'Нет данных', ha='center', va='center', transform=ax.transAxes,
                   fontsize=10, alpha=0.5)
    
    # Скрываем пустые subplots
    for idx in range(len(model_combinations), len(axes)):
        axes[idx].set_visible(False)
    
    plt.suptitle('Распределение предсказаний по всем комбинациям Парсер + Модель', 
                fontweight='bold', fontsize=16, y=1.02)
    plt.tight_layout()
    plt.savefig('prediction_distribution_all_combinations.png', dpi=300, bbox_inches='tight', facecolor='white')
    plt.show()
    print("📊 График распределения предсказаний сохранен как 'prediction_distribution_all_combinations.png'")

def create_visualizations(df, detailed_df):
    """Создание всех визуализаций для отчета (обновленная версия)"""
    try:
        plt.style.use('seaborn-v0_8-whitegrid')
        plt.rcParams['font.size'] = 10
        plt.rcParams['figure.autolayout'] = True
        
        print("\n🎨 СОЗДАНИЕ ВИЗУАЛИЗАЦИЙ:")
        print("="*50)
        
        # 1. График точности комбинаций
        print("📈 Создание графика точности комбинаций...")
        create_model_performance_chart(detailed_df)
        
        # 2. График анализа ошибок
        print("📊 Создание графика анализа ошибок...")
        create_error_analysis_chart(detailed_df)
        
        # 3. График распределения предсказаний
        print("📋 Создание графика распределения предсказаний...")
        create_prediction_distribution_chart(detailed_df)
        
        # 4. Confusion Matrix (добавьте эту функцию если нужно)
        print("🔄 Создание Confusion Matrix...")
        create_confusion_matrix_chart(detailed_df)  # Эта функция уже у вас есть
        
        print("\n✅ Все визуализации успешно созданы!")
        
    except Exception as e:
        print(f"⚠️ Ошибка при создании визуализаций: {e}")

# Основная программа
if __name__ == "__main__":
    print("🚀 ЗАПУСК АНАЛИЗА МОДЕЛЕЙ ДЕТЕКЦИИ ФИШИНГА")
    print("="*50)
    
    # 1. Загрузка моделей
    models = load_all_models()
    
    # 2. Получение тестовых URL
    test_urls = get_test_urls(legitimate_count=10, phishing_count=10)
    
    # 3. Тестирование легитимных сайтов
    print("\n🔍 ТЕСТИРОВАНИЕ ЛЕГИТИМНЫХ САЙТОВ:")
    all_results = []
    
    for i, url in enumerate(test_urls['legitimate']):
        print(f"  {i+1}. {url}")
        results = test_url_with_all_models(url, 'legitimate', models)
        all_results.extend(results)
    
    # 4. Тестирование фишинговых сайтов
    print("\n🔍 ТЕСТИРОВАНИЕ ФИШИНГОВЫХ САЙТОВ:")
    for i, url in enumerate(test_urls['phishing']):
        print(f"  {i+1}. {url}")
        results = test_url_with_all_models(url, 'phishing', models)
        all_results.extend(results)
    
    # 5. Анализ результатов
    results_df, detailed_df = analyze_results(all_results)
    
    # 6. Визуализация
    if results_df is not None and len(results_df) > 0:
        create_visualization(results_df, detailed_df)
        create_visualizations(results_df, detailed_df)
        
    
    print("\n✅ АНАЛИЗ ЗАВЕРШЕН!")