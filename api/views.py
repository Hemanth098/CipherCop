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
from . import ml_helpers  # Import the helper functions 
ml_helpers.setup_nltk()
ml_models = ml_helpers.load_all_models()
from sklearn.preprocessing import StandardScaler # Import StandardScaler
 # Assuming functions.py is in the same directory
# --- View to Serve the Homepage ---
def index(request):
    """Serves the main index.html file."""
    return render(request, 'index.html')

# --- Load Machine Learning Models ---
web_model = ml_models.get('web_model')
mobile_model_components = ml_models.get('mobile_model_components')
sentiment_model = ml_models.get('sentiment_model')
tfidf_vectorizer = ml_models.get('tfidf_vectorizer')
# 2. NEW Android Malware Model v3 (Context-Aware and Scaled)
MOBILE_MODEL_V3_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'model_app_v3.keras')
FEATURES_V3_PATH = os.path.join(os.path.dirname(__file__), 'ml_model', 'model_app_features_v3.joblib')

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
        'check_redirection', 'age_domain', 'nb_page', 'dns_a_record', 'dnssec',
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
    
    # Update with manual overrides (google_index removed from loop)
    for key in ['domain_age', 'domain_registration_length', 'web_traffic', 'page_rank']:
        if key in overrides and overrides[key] is not None and overrides[key] != '':
            features_dict[key.replace('domain_age', 'age_domain')] = int(overrides[key])
            
    return features_dict

# --- Live PageRank API Function ---
def get_domcop_page_rank(domain, api_key):
    """
    Fetches the Page Rank score from the Open PageRank API.
    Returns an integer score (0-10) or 0 if an error occurs.
    """
    if not api_key:
        print("Warning: Open PageRank API key is missing.")
        return 0

    api_url = "https://openpagerank.com/api/v1.0/getPageRank"
    headers = {"API-OPR": api_key}
    params = {"domains[]": domain}

    try:
        response = requests.get(api_url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        if data and "response" in data and len(data["response"]) > 0:
            rank = data["response"][0].get("page_rank_integer", 0)
            return int(rank)
        return 5  # Default to 5 if no rank found
    except requests.exceptions.RequestException as e:
        print(f"Error fetching Page Rank for {domain}: {e}")
        raise ValueError("Could not connect to the Page Rank service. Please check your internet connection and try again.")
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        print(f"Error parsing Open PageRank API response for {domain}: {e}")
        raise ValueError("Could not Found Page Rank score for the provided domain.")

# --- API Endpoint for Website and Chrome Extension ---
@csrf_exempt
def analyze_website(request):
    if request.method == 'POST':
        try:
            DOMCOP_API_KEY = "gwg8wgsc4o4wsg4w04g08c0ogsc88kck4owwgkc4" 
            data = json.loads(request.body)
            
            # FIX: Accept URL from either 'mainInput' (website) or 'url' (plugin)
            url_to_analyze = data.get('mainInput') or data.get('url')
            
            if not url_to_analyze:
                return JsonResponse({'error': "URL is required in the request body."}, status=400)

            # --- Real-Time PageRank Fetching using DomCop ---
            parsed_url = urlparse(url_to_analyze)
            domain = parsed_url.netloc
            page_rank_score = get_domcop_page_rank(domain, DOMCOP_API_KEY)
            
            overrides = {
                'domain_registration_length': data.get('domain_registration_length'),
                'domain_age': data.get('domain_age'),
                'web_traffic': data.get('web_traffic'),
                'page_rank': page_rank_score  # Use the fetched score from DomCop
            }

            features_dict = extract_features_from_url(url_to_analyze, overrides)
            if 'error' in features_dict:
                return JsonResponse({'error': features_dict['error']}, status=400)

            feature_order = [
                'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains', 'prefix_suffix', 'random_domain', 'shortening_service', 'path_extension', 'nb_redirection', 'nb_external_redirection', 'length_words_raw', 'char_repeat', 'shortest_words_raw', 'shortest_word_host', 'shortest_word_path', 'longest_words_raw', 'longest_word_host', 'longest_word_path', 'avg_words_raw', 'avg_word_host', 'avg_word_path', 'phish_hints', 'suspecious_tld', 'statistical_report', 'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks', 'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors', 'ratio_extErrors', 'login_form', 'external_favicon', 'links_in_tags', 'submit_email', 'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe', 'popup_window', 'safe_anchor', 'onmouseover', 'right_clic', 'empty_title', 'domain_in_ip', 'server_client_same_domain', 'check_redirection', 'age_domain', 'nb_page', 'google_index', 'dns_a_record', 'dnssec', 'whois_registered_domain', 'domain_registration_length', 'web_traffic', 'page_rank'
            ]
            
            features = np.array([[features_dict.get(k, 0) for k in feature_order]])
            
            if not web_model:
                return JsonResponse({'error': "Web model not available."}, status=503)
                
            prob = web_model.predict_proba(features)[0][1]
            score = int(prob * 100)
            
            return JsonResponse({
                'url': url_to_analyze,
                'fraudScore': score,
                'category': 'Phishing' if score > 70 else ('Legitimate - But Might Cause Phishing' if score > 50 else 'Legitimate'),
                'analysisDetails': (
                    f"Fraud score calculated as {score}%.!<br>"
                    f"Page Rank score {page_rank_score}/10 was included in the analysis.!<br>"
                    f"The site was categorized as {'Phishing' if score > 70 else ('Legitimate - But Might Cause Phishing' if score > 50 else 'Legitimate')}<br>"
                    f"because the score {'exceeded' if score > 50 else 'did not exceed'} the 50% threshold.<br>"
                ),
                'timestamp': datetime.now().isoformat()
            })

        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON in request body'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f"An unexpected server error occurred: {e}"}, status=500)
            
    return JsonResponse({'error': 'Invalid request method'}, status=405)


@csrf_exempt
def analyze_mobile_app_new(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    try:
        data = json.loads(request.body)
        app_name = data.get('mainInput')
        category = data.get('category')
        permissions_from_user = data.get('permissions', {})

        if not category:
            return JsonResponse({'error': 'App Category is a required field.'}, status=400)

        # Get a list of the permissions the user actually ticked
        ticked_permissions = [perm for perm, value in permissions_from_user.items() if value == 1]
        
        # Check for suspicious permissions based on the rules in ml_helpers.py
        suspicious_permissions = ml_helpers.check_fraud_by_rules(category, ticked_permissions)
        suspicious_count = len(suspicious_permissions)
        
        fraud_score = 0
        analysis_details = ""
        final_category = "Low-Risk App"

        # --- Implement the New Rule Set ---

        if suspicious_count >= 5:
            # Rule: 5 or more violations is definitely fraud.
            fraud_score = 95
            final_category = "High-Risk App"
            perm_list = ", ".join(suspicious_permissions)
            analysis_details = f"High-Risk Detected. The app requests {suspicious_count} permissions that are highly unusual for a '{category}' app, including: {perm_list}."

        elif 1 <= suspicious_count <= 4:
            # Rule: 1 to 4 violations require a review check.
            analysis_details = f"The app requests {suspicious_count} suspicious permission(s) for a '{category}' app. Checking user reviews to confirm..."
            
            found_app_id = ml_helpers.get_app_id_from_name(app_name)
            
            if not found_app_id:
                # Special Rule: If the app has ANY violation AND cannot be found on the Play Store, it's fraud.
                fraud_score = 90
                final_category = "High-Risk App"
                analysis_details = f"High-Risk Detected. The app has {suspicious_count} suspicious permission(s) and could not be found on the Google Play Store, which is a strong indicator of fraudulent activity."
            else:
                # App was found, so proceed to analyze reviews.
                sentiment_score = 0.5  # Default to neutral
                review_texts = ml_helpers.scrape_review_texts(found_app_id)
                
                if review_texts and sentiment_model and tfidf_vectorizer:
                    processed_reviews = [ml_helpers.PreProcessText(r) for r in review_texts]
                    predictions = sentiment_model.predict(tfidf_vectorizer.transform(processed_reviews))
                    numerical_predictions = [1 if p == 'positive' else 0 for p in predictions]
                    if numerical_predictions:
                        sentiment_score = np.mean(numerical_predictions)
                
                # Rule: Are the reviews positive enough to overlook the violations?
                if sentiment_score > 0.6: # More than 60% positive reviews
                    fraud_score = 55
                    final_category = "Medium-Risk App"
                    analysis_details += f" User reviews are generally positive (Sentiment Score: {sentiment_score:.0%}), which lowers the risk. However, caution is still advised due to the unusual permissions."
                else:
                    fraud_score = 85
                    final_category = "High-Risk App"
                    analysis_details += f" The app's user reviews are neutral or negative (Sentiment Score: {sentiment_score:.0%}). Combined with the suspicious permissions, this indicates a high risk."
        
        else: # suspicious_count == 0
            # Rule: No violations, the app is considered safe.
            fraud_score = 10
            final_category = "Low-Risk App"
            analysis_details = f"Low-Risk Detected. No suspicious permissions were found for the '{category}' category. The app appears to follow standard practices."

        return JsonResponse({
            'url': app_name,
            'fraudScore': fraud_score,
            'category': final_category,
            'analysisDetails': analysis_details,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        return JsonResponse({'error': f"A server error occurred: {str(e)}"}, status=500)