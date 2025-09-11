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
from . import gemini
from pyaxmlparser import APK
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
import uuid # To generate unique filenames for temporary storage
 # Assuming functions.py is in the same directory
# --- View to Serve the Homepage ---


# Add these imports at the top of your views.py
import tempfile
import hashlib


# ... (keep all your existing imports: json, joblib, np, pd, os, etc.)

# --- View to Serve the Homepage ---
def index(request):
    """Serves the main index.html file."""
    return render(request, 'index.html')

# --- Load ALL Machine Learning Models ---

# (Keep your existing web_model and mobile_app_model_v3 loading logic here)
# ...

# --- NEW: Load APK Malware Models ---
try:
    apk_model = joblib.load(os.path.join(os.path.dirname(__file__), 'ml_model', 'best_malware_model.joblib'))
    apk_selector = joblib.load(os.path.join(os.path.dirname(__file__), 'ml_model', 'feature_selector.joblib'))
    apk_encoder = joblib.load(os.path.join(os.path.dirname(__file__), 'ml_model', 'label_encoder.joblib'))
    apk_feature_names = joblib.load(os.path.join(os.path.dirname(__file__), 'ml_model', 'feature_names.joblib'))
    print("✅ Successfully loaded APK malware model and preprocessors.")
except Exception as e:
    print(f"⚠️ Warning: Could not load APK malware models. Error: {e}")
    apk_model = None

# --- (Keep all existing helper functions and analyze_website / analyze_mobile_app_new views) ---
# ... (extract_features_from_url, get_domcop_page_rank, analyze_website, analyze_mobile_app_new, etc.)

# --- NEW: Helper Functions for APK Analysis ---

def extract_permissions_from_apk(apk_path):
    try:
        apk = APK(apk_path)
        return apk.permissions
    except Exception as e:
        print(f"❌ Error processing APK permissions: {e}")
        return None

def create_apk_feature_vector(permissions, all_features):
    feature_vector = np.zeros(len(all_features))
    feature_index = {feature: i for i, feature in enumerate(all_features)}
    for p in permissions:
        if p in feature_index:
            feature_vector[feature_index[p]] = 1
    return feature_vector.reshape(1, -1)

def get_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# --- NEW: API Endpoint for APK Analysis ---
@csrf_exempt
def analyze_apk(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Invalid request method'}, status=405)

    if not apk_model:
        return JsonResponse({'error': "APK analysis model is not available."}, status=503)

    if 'apk_file' not in request.FILES:
        return JsonResponse({'error': 'No APK file was uploaded.'}, status=400)

    # Use a temporary file to handle the upload
    uploaded_apk = request.FILES['apk_file']
    apk_path = ""
    
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as temp_f:
            for chunk in uploaded_apk.chunks():
                temp_f.write(chunk)
            apk_path = temp_f.name

        # --- 1. Safety Check (ML Model) ---
        permissions = extract_permissions_from_apk(apk_path)
        if permissions is None:
            return JsonResponse({'error': 'Could not parse the uploaded file. It may not be a valid APK.'}, status=400)

        feature_vector = create_apk_feature_vector(permissions, apk_feature_names)
        vector_selected = apk_selector.transform(feature_vector)
        prediction_encoded = apk_model.predict(vector_selected)
        safety_prediction = apk_encoder.inverse_transform(prediction_encoded)[0]

        # --- 2. Authenticity Check (VirusTotal API) ---
        VT_API_KEY = "bfff6b4bcd78a175a3846660095d1057f4b434188562ef059ef0b5478d2f1b50" # It's better to use environment variables
        file_hash = get_file_hash(apk_path)
        headers = {'x-apikey': VT_API_KEY}
        vt_url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        
        authenticity_prediction = "M" # Default assumption
        
        try:
            response = requests.get(vt_url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                stats = data.get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            
            # A more robust check: Is the file flagged by any security vendors?
            if malicious_count > 0 or suspicious_count > 0:
                authenticity_prediction = "Modified"
                vt_details = (f"VirusTotal reports {malicious_count} malicious and "
                            f"{suspicious_count} suspicious detections. High risk.")
            else:
                # If there are no malicious flags, we can have higher confidence it's official/unaltered.
                authenticity_prediction = "Official"
                vt_details = "VirusTotal analysis found no malicious detections, suggesting this is a clean, official application."
            
        except requests.RequestException:
            # If VT fails, we can't verify, so we stick with the default
            print("⚠️ Warning: Could not connect to VirusTotal API for authenticity check.")
            pass

        # --- 3. Combine and Respond ---
        is_safe = (safety_prediction == 'Benign')
        is_official = (authenticity_prediction == 'Official')
        
        if is_official and is_safe:
            category = "Safe, Official App"
            details = "This appears to be the original, unmodified app from the developer, and our permission analysis found no signs of malware."
        elif is_official and not is_safe:
            category = "Malicious Official App"
            details = "This appears to be an official app, but our model detected a malicious pattern of permissions. This is a high-risk application."
        elif not is_official and is_safe:
            category = "Potentially Safe Mod APK"
            details = "The app appears to be modified. While our model found no malicious permissions, use it with caution as modifications can introduce hidden risks."
        else: # Not official and not safe
            category = "Malicious Mod APK"
            details = "This app is a modified version AND our model detected malicious permission patterns. This is the highest risk category; avoid using it."

        return JsonResponse({
            'url': uploaded_apk.name,
            'category': category,
            'analysisDetails': details,
            'safetyPrediction': safety_prediction,
            'authenticityPrediction': authenticity_prediction,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        return JsonResponse({'error': f'An unexpected server error occurred: {str(e)}'}, status=500)
    finally:
        # Clean up the temporary file
        if os.path.exists(apk_path):
            os.remove(apk_path)

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
            gemini.load_gemini_api()
            geminires = gemini.gemini_analyze(url_to_analyze, gemini.get_gemini_model())
            print("Gemini Analysis Result:", geminires)  # Debugging line
            x  = gemini.parse_analysis_to_list(geminires)
            x = dict(x)
            fraud_score = gemini.calculate_fraud_percentage(x)
            print("Calculated Fraud Score:", fraud_score)  # Debugging line
            if x.get("confidence", "").lower() == "high":
                return JsonResponse({
                    'url': url_to_analyze,
                    'fraudScore': gemini.calculate_fraud_percentage(x),
                    'category': x.get("verdict", "Unknown"),
                    'analysisDetails': f"{x.get("verdict", "Unknown"),}:{x.get("reasons", "No reasons provided.")}",
                    'timestamp': datetime.now().isoformat()
                })
            else:
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
                    'fraudScore': gemini.calculate_fraud_percentage(x)+score//2,
                    'category': 'Phishing' if score > 70 else ('Legitimate - But Might Cause Phishing' if score > 50 else 'Legitimate'),
                    'analysisDetails': (
                        f"Fraud score calculated as {score}%.!<br>"
                        f"Page Rank score {page_rank_score}/10 was included in the analysis.!<br>"
                        f"The site was categorized as {'Phishing' if score > 70 else ('Legitimate - But Might Cause Phishing' if (score > 50 and score < 70) else 'Legitimate')}<br>"
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

        if not app_name or not category:
            return JsonResponse({'error': 'App Name and Category are required fields.'}, status=400)

        # --- Step 1: Gather Initial Inputs ---
        ticked_permissions = [perm for perm, value in permissions_from_user.items() if value == 1]
        found_app_id = ml_helpers.get_app_id_from_name(app_name)

        # --- Step 2: Handle Edge Case (No Inputs) ---
        # If the app can't be found AND no permissions were given, we can't do anything.
        if not found_app_id and not ticked_permissions:
            return JsonResponse({
                'error': 'Input Error: The app was not found and no permissions were selected. Please provide a valid app name or select permissions to analyze.'
            }, status=400)

        # --- Step 3: Conditional Analysis Logic ---
        
        # --- CASE 1: App NOT found, but permissions ARE provided ---
        if not found_app_id:
            analysis_details = (
                f"<b>Warning: App not found on Play Store.</b> Analysis is based solely on the permissions you provided. "
                f"Unverified apps carry inherent risk."
            )
            suspicious_permissions = ml_helpers.check_fraud_by_rules(category, ticked_permissions)
            suspicious_count = len(suspicious_permissions)
            
            # Scoring: Start with a base risk for being unverified, then add permission penalties.
            base_risk_unverified = 30 
            permission_risk = suspicious_count * 15
            fraud_score = int(min(base_risk_unverified + permission_risk, 99))
            
            if suspicious_count > 0:
                perm_list = ", ".join(suspicious_permissions)
                analysis_details += (
                    f" The app requests <b>{suspicious_count} suspicious permission(s)</b> for a '{category}' app: {perm_list}."
                )

        # --- CASE 2: App IS found (permissions may or may not be provided) ---
        else:
            # Perform sentiment analysis since the app was found
            sentiment_score = 0.5  # Default to neutral
            review_texts = ml_helpers.scrape_review_texts(found_app_id)
            review_analysis_text = "Could not retrieve user reviews; assuming neutral sentiment. "
            
            if review_texts and sentiment_model and tfidf_vectorizer:
                processed_reviews = [ml_helpers.PreProcessText(r) for r in review_texts]
                predictions = sentiment_model.predict(tfidf_vectorizer.transform(processed_reviews))
                numerical_predictions = [1 if p == 'positive' else 0 for p in predictions]
                if numerical_predictions:
                    sentiment_score = np.mean(numerical_predictions)
                review_analysis_text = f"User review sentiment is {sentiment_score:.0%} positive. "
            
            # Calculate permission risk (will be 0 if no permissions were ticked)
            suspicious_permissions = ml_helpers.check_fraud_by_rules(category, ticked_permissions)
            suspicious_count = len(suspicious_permissions)
            permission_risk = suspicious_count * 15

            # Base score from sentiment (0-50). 0=perfect reviews, 50=terrible reviews.
            sentiment_risk = (1 - sentiment_score) * 50
            
            # Combine scores
            fraud_score = int(min(5 + sentiment_risk + permission_risk, 99))

            # Generate analysis details based on what was provided
            analysis_details = review_analysis_text
            if ticked_permissions:
                if suspicious_count > 0:
                    perm_list = ", ".join(suspicious_permissions)
                    analysis_details += (
                        f"It also requests <b>{suspicious_count} suspicious permission(s)</b> for a '{category}' app: {perm_list}."
                    )
                else:
                    analysis_details += "No suspicious permissions were found."
            else:
                analysis_details += "<b>No permissions were provided for analysis.</b> The score is based only on public reviews."

        # --- Step 4: Determine Final Category & Return Response ---
        if fraud_score > 75:
            final_category = "High-Risk App"
        elif fraud_score > 40:
            final_category = "Medium-Risk App"
        else:
            final_category = "Low-Risk App"
            
        return JsonResponse({
            'url': app_name,
            'fraudScore': fraud_score,
            'category': final_category,
            'analysisDetails': analysis_details,
            'timestamp': datetime.now().isoformat()
        })

    except Exception as e:
        return JsonResponse({'error': f"A server error occurred: {str(e)}"}, status=500)