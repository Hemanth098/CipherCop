import json
import joblib
import numpy as np
import pandas as pd
import os
from datetime import datetime
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
import re
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import itertools
import tensorflow as tf

# --- View to Serve the Homepage ---
def index(request):
    return render(request, 'index.html')

# --- Load Machine Learning Models ---

# 1. Website Phishing Model
WEB_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'model_web.joblib')
try:
    web_model = joblib.load(WEB_MODEL_PATH)
    print("Successfully loaded website phishing model (model_web.joblib).")
except FileNotFoundError:
    print(f"Warning: Website model not found at {WEB_MODEL_PATH}. Using dummy predictions.")
    web_model = None

def predict_dummy(features):
    return np.random.rand(1, 2)

# 2. Original Android Malware Model (Permissions-based)
OLD_MOBILE_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'model_app.keras')
FEATURES_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'model_app_features.joblib')

try:
    old_mobile_model = tf.keras.models.load_model(OLD_MOBILE_MODEL_PATH, compile=False)
    mobile_features = joblib.load(FEATURES_PATH)
    print(f"Successfully loaded original Android malware model (model_app.keras) with {len(mobile_features['columns'])} features.")
except Exception as e:
    print(f"Warning: Could not load original Android malware model. Using dummy predictions. Error: {e}")
    old_mobile_model = None
    mobile_features = None

# 3. New Mobile App Model (from user upload)
NEW_MOBILE_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'model_app.joblib')
try:
    new_mobile_model = joblib.load(NEW_MOBILE_MODEL_PATH)
    print("Successfully loaded new mobile app model (model_app.joblib).")
except Exception as e:
    print(f"Warning: Could not load new mobile app model from model_app.joblib. Error: {e}")
    new_mobile_model = None

# --- Helper function for word extraction ---
def get_words(text):
    if not text:
        return []
    words = re.split(r'[\./\-_?=&;@]', text)
    return [word for word in words if word]


# --- Feature Extraction for Website Model ---
def extract_features_from_url(url, overrides=None):
    if overrides is None:
        overrides = {}
        
    feature_columns = [
        'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and',
        'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star',
        'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com',
        'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url', 'ratio_digits_host',
        'punycode', 'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
        'nb_subdomains', 'prefix_suffix', 'random_domain', 'shortening_service', 'path_extension',
        'nb_redirection', 'nb_external_redirection', 'length_words_raw', 'char_repeat',
        'shortest_words_raw', 'shortest_word_host', 'shortest_word_path', 'longest_words_raw',
        'longest_word_host', 'longest_word_path', 'avg_words_raw', 'avg_word_host',
        'avg_word_path', 'phish_hints', 'suspecious_tld', 'statistical_report', 'nb_hyperlinks',
        'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks', 'nb_extCSS',
        'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors', 'ratio_extErrors',
        'login_form', 'external_favicon', 'links_in_tags', 'submit_email', 'ratio_intMedia',
        'ratio_extMedia', 'sfh', 'iframe', 'popup_window', 'safe_anchor', 'onmouseover',
        'right_clic', 'empty_title', 'domain_in_ip', 'server_client_same_domain',
        'check_redirection', 'age_domain', 'nb_page', 'google_index', 'dns_a_record', 'dnssec',
        'whois_registered_domain', 'domain_registration_length', 'web_traffic', 'page_rank'
    ]
    features_dict = {feature: 0 for feature in feature_columns}

    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname if parsed_url.hostname else ''
        path = parsed_url.path
        
        if not hostname:
            return {'error': 'Invalid URL provided.'}

        features_dict['length_url'] = len(url)
        features_dict['length_hostname'] = len(hostname)
        features_dict['ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname) else 0
        features_dict['nb_dots'] = url.count('.')
        features_dict['nb_hyphens'] = url.count('-')
        features_dict['nb_at'] = url.count('@')
        features_dict['nb_qm'] = url.count('?')
        features_dict['nb_and'] = url.count('&')
        features_dict['nb_eq'] = url.count('=')
        features_dict['nb_underscore'] = url.count('_')
        features_dict['nb_tilde'] = url.count('~')
        features_dict['nb_percent'] = url.count('%')
        features_dict['nb_slash'] = url.count('/')
        features_dict['nb_dslash'] = url.count('//')
        features_dict['nb_www'] = hostname.lower().count('www')
        features_dict['nb_com'] = url.lower().count('.com')
        features_dict['https_token'] = 1 if 'https' in parsed_url.scheme.lower() else 0
        
        digits_url = sum(c.isdigit() for c in url)
        digits_host = sum(c.isdigit() for c in hostname)
        features_dict['ratio_digits_url'] = digits_url / len(url) if len(url) > 0 else 0
        features_dict['ratio_digits_host'] = digits_host / len(hostname) if len(hostname) > 0 else 0
        
        features_dict['port'] = 1 if parsed_url.port else 0
        features_dict['nb_subdomains'] = len(hostname.split('.')) - 2 if hostname and '.' in hostname else 0
        features_dict['prefix_suffix'] = 1 if '-' in hostname else 0
        features_dict['shortening_service'] = 1 if any(s in hostname for s in ['bit.ly', 'goo.gl', 't.co']) else 0

        phish_keywords = ['login', 'secure', 'account', 'webscr', 'signin', 'banking', 'confirm', 'ebay', 'paypal']
        features_dict['phish_hints'] = sum(url.lower().count(keyword) for keyword in phish_keywords)
        
        if url:
            max_chars = [len(list(g)) for k, g in itertools.groupby(url)]
            features_dict['char_repeat'] = max(max_chars) if max_chars else 0

        url_words, host_words, path_words = get_words(url), get_words(hostname), get_words(path)
        
        if url_words:
            features_dict['length_words_raw'] = len(url_words)
            word_lengths = [len(w) for w in url_words]
            features_dict['shortest_words_raw'] = min(word_lengths) if word_lengths else 0
            features_dict['longest_words_raw'] = max(word_lengths) if word_lengths else 0
            features_dict['avg_words_raw'] = sum(word_lengths) / len(word_lengths) if word_lengths else 0

        if host_words:
            host_word_lengths = [len(w) for w in host_words]
            features_dict['shortest_word_host'] = min(host_word_lengths) if host_word_lengths else 0
            features_dict['longest_word_host'] = max(host_word_lengths) if host_word_lengths else 0
            features_dict['avg_word_host'] = sum(host_word_lengths) / len(host_word_lengths) if host_word_lengths else 0

        if path_words:
            path_word_lengths = [len(w) for w in path_words]
            features_dict['shortest_word_path'] = min(path_word_lengths) if path_word_lengths else 0
            features_dict['longest_word_path'] = max(path_word_lengths) if path_word_lengths else 0
            features_dict['avg_word_path'] = sum(path_word_lengths) / len(path_word_lengths) if path_word_lengths else 0

    except Exception as e:
        return {'error': f'Could not parse URL: {e}'}

    try:
        if 'domain_age' in overrides and overrides['domain_age']:
            features_dict['age_domain'] = int(overrides['domain_age'])
        if 'domain_registration_length' in overrides and overrides['domain_registration_length']:
            features_dict['domain_registration_length'] = int(overrides['domain_registration_length'])

        if 'domain_age' not in overrides or 'domain_registration_length' not in overrides:
            domain_info = whois.whois(hostname)
            if 'domain_age' not in overrides:
                if domain_info.creation_date:
                    c_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                    age = (datetime.now() - c_date).days
                    features_dict['age_domain'] = age if age >= 0 else 0
            
            if 'domain_registration_length' not in overrides:
                if domain_info.expiration_date and domain_info.creation_date:
                    e_date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date
                    c_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
                    reg_len = (e_date - c_date).days
                    features_dict['domain_registration_length'] = reg_len if reg_len > 0 else 0
            
            features_dict['whois_registered_domain'] = 1 if domain_info.domain_name else 0
    except Exception:
        features_dict['age_domain'] = -1
        features_dict['domain_registration_length'] = -1

    try:
        response = requests.get(url, timeout=5, headers={'User-Agent': 'Mozilla/5.0'}, allow_redirects=True)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            features_dict['login_form'] = 1 if soup.find('form', {'action': re.compile(r'login', re.I)}) else 0
            features_dict['empty_title'] = 1 if not soup.title or not soup.title.string.strip() else 0
            links = soup.find_all('a', href=True)
            nb_hyperlinks = len(links)
            features_dict['nb_hyperlinks'] = nb_hyperlinks
    except requests.exceptions.RequestException:
        pass # Allow analysis to continue with partial data

    if 'google_index' in overrides and overrides['google_index']:
        features_dict['google_index'] = int(overrides['google_index'])
    if 'page_rank' in overrides and overrides['page_rank']:
        features_dict['page_rank'] = int(overrides['page_rank'])
    if 'web_traffic' in overrides and overrides['web_traffic']:
        features_dict['web_traffic'] = int(overrides['web_traffic'])

    return features_dict

# --- Preprocessing for the Original Mobile App Model ---
def preprocess_original_app_permissions(permissions_dict, features_data):
    required_columns = features_data['columns']
    df = pd.DataFrame([permissions_dict])
    df_reindexed = df.reindex(columns=required_columns, fill_value=0)
    return df_reindexed.to_numpy()


# --- API Endpoints ---

@csrf_exempt
def analyze_website(request):
    """Handles website analysis using the web_model."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url_to_analyze = data.get('mainInput')

            if not url_to_analyze:
                return JsonResponse({'error': "URL is required."}, status=400)

            override_keys = ['domain_registration_length', 'domain_age', 'web_traffic', 'page_rank', 'google_index']
            overrides = {key: data.get(key) for key in override_keys if data.get(key)}
            features_dict = extract_features_from_url(url_to_analyze, overrides)

            if 'error' in features_dict:
                return JsonResponse({'error': features_dict['error']}, status=400)

            feature_order = [
                'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and',
                'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star',
                'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com',
                'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url', 'ratio_digits_host',
                'punycode', 'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain',
                'nb_subdomains', 'prefix_suffix', 'random_domain', 'shortening_service', 'path_extension',
                'nb_redirection', 'nb_external_redirection', 'length_words_raw', 'char_repeat',
                'shortest_words_raw', 'shortest_word_host', 'shortest_word_path', 'longest_words_raw',
                'longest_word_host', 'longest_word_path', 'avg_words_raw', 'avg_word_host',
                'avg_word_path', 'phish_hints', 'suspecious_tld', 'statistical_report', 'nb_hyperlinks',
                'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks', 'nb_extCSS',
                'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors', 'ratio_extErrors',
                'login_form', 'external_favicon', 'links_in_tags', 'submit_email', 'ratio_intMedia',
                'ratio_extMedia', 'sfh', 'iframe', 'popup_window', 'safe_anchor', 'onmouseover',
                'right_clic', 'empty_title', 'domain_in_ip', 'server_client_same_domain',
                'check_redirection', 'age_domain', 'nb_page', 'google_index', 'dns_a_record', 'dnssec',
                'whois_registered_domain', 'domain_registration_length', 'web_traffic', 'page_rank'
            ]
            feature_values = [features_dict.get(k, 0) for k in feature_order]
            features_for_model = np.array([feature_values])
            
            if web_model:
                probabilities = web_model.predict_proba(features_for_model)[0]
            else:
                probabilities = predict_dummy(features_for_model)[0]
            
            phishing_probability = probabilities[1]
            fraud_score = int(phishing_probability * 100)
            is_fraudulent = fraud_score > 70
            category = 'Phishing' if is_fraudulent else 'Legitimate'

            response_data = {
                'url': url_to_analyze,
                'fraudScore': fraud_score,
                'category': category,
                'analysisDetails': "Analysis based on lexical, domain, and content features.",
                'timestamp': datetime.now().isoformat()
            }
            return JsonResponse(response_data)
        except Exception as e:
            return JsonResponse({'error': f"A server error occurred: {str(e)}"}, status=500)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def analyze_mobile_app(request):
    """Handles original mobile app analysis (permissions-based) using the old_mobile_model."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            permissions_list = data.get('permissions')

            if not permissions_list or not isinstance(permissions_list, list):
                return JsonResponse({'error': "A JSON array of permissions is required."}, status=400)

            if not old_mobile_model or not mobile_features:
                raise RuntimeError("Original Android malware model is not available on the server.")

            permissions_dict = {perm: 1 for perm in permissions_list}
            features_for_model = preprocess_original_app_permissions(permissions_dict, mobile_features)
            
            malware_probability = old_mobile_model.predict(features_for_model)[0][0]
            
            OPTIMAL_THRESHOLD = 0.45
            fraud_score = int(malware_probability * 100)
            is_malicious = malware_probability > OPTIMAL_THRESHOLD
            
            category = 'Malicious App' if is_malicious else 'Safe App'
            details = (
                f"High risk detected. Analysis of {len(permissions_list)} provided permissions "
                "matches patterns commonly seen in malware."
            ) if is_malicious else (
                f"Analysis of {len(permissions_list)} provided permissions suggests the app is safe. "
                "No high-risk combinations were found by our model."
            )

            response_data = {
                'url': f"{len(permissions_list)} permissions analyzed",
                'fraudScore': fraud_score,
                'category': category,
                'analysisDetails': details,
                'timestamp': datetime.now().isoformat()
            }
            return JsonResponse(response_data)
        except Exception as e:
            return JsonResponse({'error': f"A server error occurred: {str(e)}"}, status=500)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def analyze_mobile_app_new(request):
    """Handles new mobile app analysis using the form data and the new_mobile_model."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            app_id = data.get('mainInput', 'N/A')
            
            if not new_mobile_model:
                raise RuntimeError("The new mobile app model (model_app.joblib) is not available.")
            
            # This model expects 51 features based on its architecture.
            # We are using the 4 features from the form and padding the rest.
            # For production, you would implement full feature extraction logic.
            
            app_age = int(data.get('app_age') or 0)
            downloads = data.get('downloads')
            user_rating = float(data.get('user_rating') or 0.0)
            permissions_count = int(data.get('permissions') or 0)
            
            # Simple parsing for downloads text like '1M+'. A more robust solution would be needed for production.
            downloads_numeric = 0
            if isinstance(downloads, str):
                downloads_lower = downloads.lower()
                if 'm+' in downloads_lower:
                    downloads_numeric = int(float(downloads_lower.replace('m+', '')) * 1000000)
                elif 'k+' in downloads_lower:
                    downloads_numeric = int(float(downloads_lower.replace('k+', '')) * 1000)
            
            # Construct the feature vector (total 51 features expected by the model)
            # The exact feature order is unknown, so this is a placeholder mapping.
            feature_vector = np.zeros(51)
            feature_vector[0] = app_age
            feature_vector[1] = downloads_numeric 
            feature_vector[2] = user_rating
            feature_vector[3] = permissions_count
            
            features_for_model = np.array([feature_vector])
            
            # Predict using the loaded joblib Keras model
            prediction = new_mobile_model.predict(features_for_model)
            malware_probability = prediction[0][0]

            fraud_score = int(malware_probability * 100)
            is_malicious = fraud_score > 50 # Using a standard 50% threshold
            
            category = 'High-Risk App' if is_malicious else 'Low-Risk App'
            details = (
                f"Analysis based on app age, downloads, rating, and permission count. "
                f"The model assigned a risk score of {fraud_score}, indicating potential malicious behavior."
            ) if is_malicious else (
                f"Analysis based on app age, downloads, rating, and permission count. "
                f"The model assigned a risk score of {fraud_score}, indicating the app is likely safe."
            )

            response_data = {
                'url': app_id,
                'fraudScore': fraud_score,
                'category': category,
                'analysisDetails': details,
                'timestamp': datetime.now().isoformat()
            }
            return JsonResponse(response_data)
        except Exception as e:
            return JsonResponse({'error': f"A server error occurred: {str(e)}"}, status=500)
    return JsonResponse({'error': 'Invalid request method'}, status=405)

