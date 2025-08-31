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
from sklearn.preprocessing import StandardScaler # Import StandardScaler

# --- View to Serve the Homepage ---
def index(request):
    """Serves the main index.html file."""
    return render(request, 'index.html')

# --- Load Machine Learning Models ---

# 1. Website Phishing Model (Unchanged)
WEB_MODEL_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'model_web.joblib')
try:
    web_model = joblib.load(WEB_MODEL_PATH)
    print("Successfully loaded website phishing model (model_web.joblib).")
except FileNotFoundError:
    print(f"Warning: Website model not found at {WEB_MODEL_PATH}.")
    web_model = None

# 2. NEW Android Malware Model v3 (Context-Aware and Scaled)
MOBILE_MODEL_V3_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'model_app_v3.keras')
FEATURES_V3_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'model_app_features_v3.joblib')
# SCALER_V3_PATH is no longer needed

try:
    mobile_app_model = tf.keras.models.load_model(MOBILE_MODEL_V3_PATH, compile=False)
    features_data = joblib.load(FEATURES_V3_PATH)
    
    # Reconstruct the scaler from saved parameters to avoid version conflicts
    scaler = StandardScaler()
    scaler.mean_ = features_data['scaler_mean']
    scaler.scale_ = features_data['scaler_scale']
    
    mobile_app_features = features_data['columns']
    OPTIMAL_THRESHOLD = features_data['optimal_threshold']
    scaled_columns = features_data['scaled_columns']
    
    print(f"Successfully loaded Android malware model v3 with {len(mobile_app_features)} features.")
    print(f"Using optimal threshold of {OPTIMAL_THRESHOLD:.4f}")
except Exception as e:
    print(f"Warning: Could not load the Android malware model v3 and its components. Error: {e}")
    mobile_app_model = None
    scaler = None # Ensure scaler is None if loading fails

# (Helper functions and analyze_website view remain unchanged)
# --- Helper function for word extraction ---
def get_words(text):
    if not text: return []
    words = re.split(r'[\./\-_?=&;@]', text)
    return [word for word in words if word]

# --- Feature Extraction for Website Model ---
def extract_features_from_url(url, overrides=None):
    if overrides is None: overrides = {}
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
        hostname = parsed_url.hostname or ''
        path = parsed_url.path
        if not hostname: return {'error': 'Invalid URL provided.'}
        features_dict.update({
            'length_url': len(url), 'length_hostname': len(hostname),
            'ip': 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
            'nb_dots': url.count('.'), 'nb_hyphens': url.count('-'), 'nb_at': url.count('@'),
            'nb_qm': url.count('?'), 'nb_and': url.count('&'), 'nb_eq': url.count('='),
            'nb_underscore': url.count('_'), 'nb_tilde': url.count('~'), 'nb_percent': url.count('%'),
            'nb_slash': url.count('/'), 'nb_dslash': url.count('//'), 'nb_www': hostname.lower().count('www'),
            'nb_com': url.lower().count('.com'), 'https_token': 1 if 'https' in parsed_url.scheme.lower() else 0,
            'ratio_digits_url': sum(c.isdigit() for c in url) / len(url) if url else 0,
            'ratio_digits_host': sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0,
            'port': 1 if parsed_url.port else 0, 'nb_subdomains': len(hostname.split('.')) - 2 if '.' in hostname else 0,
            'prefix_suffix': 1 if '-' in hostname else 0,
            'shortening_service': 1 if any(s in hostname for s in ['bit.ly', 'goo.gl', 't.co']) else 0,
            'phish_hints': sum(url.lower().count(k) for k in ['login', 'secure', 'account', 'webscr', 'signin', 'banking', 'confirm'])
        })
        if url: features_dict['char_repeat'] = max(len(list(g)) for _, g in itertools.groupby(url)) if url else 0
        url_words, host_words, path_words = get_words(url), get_words(hostname), get_words(path)
        if url_words:
            wl = [len(w) for w in url_words]
            features_dict.update({'length_words_raw': len(url_words), 'shortest_words_raw': min(wl), 'longest_words_raw': max(wl), 'avg_words_raw': sum(wl)/len(wl)})
        if host_words:
            wl = [len(w) for w in host_words]
            features_dict.update({'shortest_word_host': min(wl), 'longest_word_host': max(wl), 'avg_word_host': sum(wl)/len(wl)})
        if path_words:
            wl = [len(w) for w in path_words]
            features_dict.update({'shortest_word_path': min(wl), 'longest_word_path': max(wl), 'avg_word_path': sum(wl)/len(wl)})
    except Exception as e: return {'error': f'URL parsing failed: {e}'}
    try:
        domain_info = whois.whois(hostname)
        if domain_info.creation_date:
            c_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            features_dict['age_domain'] = (datetime.now() - c_date).days
        if domain_info.expiration_date and domain_info.creation_date:
            e_date = domain_info.expiration_date[0] if isinstance(domain_info.expiration_date, list) else domain_info.expiration_date
            c_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            features_dict['domain_registration_length'] = (e_date - c_date).days
        features_dict['whois_registered_domain'] = 1 if domain_info.domain_name else 0
    except Exception:
        features_dict.update({'age_domain': -1, 'domain_registration_length': -1})
    for key in ['domain_age', 'domain_registration_length', 'web_traffic', 'page_rank', 'google_index']:
        if key in overrides and overrides[key]: features_dict[key.replace('domain_age', 'age_domain')] = int(overrides[key])
    return features_dict

# --- API Endpoints ---
@csrf_exempt
def analyze_website(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url_to_analyze = data.get('mainInput')
            if not url_to_analyze: return JsonResponse({'error': "URL is required."}, status=400)
            overrides = {k: data.get(k) for k in ['domain_registration_length', 'domain_age', 'web_traffic', 'page_rank']}
            features_dict = extract_features_from_url(url_to_analyze, overrides)
            if 'error' in features_dict: return JsonResponse({'error': features_dict['error']}, status=400)
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
            features = np.array([[features_dict.get(k, 0) for k in feature_order]])
            if not web_model: return JsonResponse({'error': "Web model not available."}, status=503)
            prob = web_model.predict_proba(features)[0][1]
            score = int(prob * 100)
            return JsonResponse({
                'url': url_to_analyze, 'fraudScore': score,
                'category': 'Phishing' if score > 70 else 'Legitimate',
                'analysisDetails': "Analysis complete.", 'timestamp': datetime.now().isoformat()
            })
        except Exception as e: return JsonResponse({'error': f"Server error: {e}"}, status=500)
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def analyze_mobile_app_new(request):
    """Handles new mobile app analysis using the v3 model."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            app_id = data.get('mainInput', 'N/A')
            
            if not all([mobile_app_model, mobile_app_features, scaler]):
                raise RuntimeError("The mobile app model v3 and its components are not available.")

            # Create a dictionary with all required features, initialized to 0
            feature_dict = {col: 0 for col in mobile_app_features}
            
            # --- Populate the feature dictionary from incoming data ---
            # Contextual features
            feature_dict['Rating'] = float(data.get('rating', 0.0))
            feature_dict['Number of ratings'] = int(data.get('num_ratings', 0))
            feature_dict['Dangerous permissions count'] = int(data.get('dangerous_permissions_count', 0))
            
            # One-hot encoded category
            category = data.get('category')
            if category:
                category_column = f"Category_{category}"
                if category_column in feature_dict:
                    feature_dict[category_column] = 1

            # Permissions
            permissions = data.get('permissions', {})
            for perm, value in permissions.items():
                if perm in feature_dict:
                    feature_dict[perm] = value
            
            # Create a DataFrame from the dictionary to ensure correct column order for scaling
            live_df = pd.DataFrame([feature_dict])
            
            # --- CRUCIAL: Scale the numerical features using the loaded scaler ---
            live_df[scaled_columns] = scaler.transform(live_df[scaled_columns])
            
            # Ensure final feature vector is in the exact order the model was trained on
            feature_vector = [live_df.iloc[0][col] for col in mobile_app_features]
            # --- FIX: Ensure the data type matches the model's expectation ---
            features_for_model = np.array([feature_vector], dtype=np.float32)
            
            # Predict
            malware_probability = mobile_app_model.predict(features_for_model)[0][0]
            fraud_score = int(malware_probability * 100)
            is_malicious = malware_probability > OPTIMAL_THRESHOLD
            
            category = 'High-Risk App' if is_malicious else 'Low-Risk App'
            details = (
                f"The model assigned a risk score of {fraud_score}. This score is based on the app's category, user ratings, and the permissions it requests. " +
                ("A high score suggests a pattern consistent with malicious applications." if is_malicious else "A low score suggests the app is likely safe.")
            )

            response_data = {
                'url': app_id, 'fraudScore': fraud_score, 'category': category,
                'analysisDetails': details, 'timestamp': datetime.now().isoformat()
            }
            return JsonResponse(response_data)
        except Exception as e:
            return JsonResponse({'error': f"A server error occurred: {str(e)}"}, status=500)
    return JsonResponse({'error': 'Invalid request method'}, status=405)

