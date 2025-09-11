import os
import joblib
import numpy as np
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from bs4 import BeautifulSoup
ALLOWED_PERMISSIONS = {
    'Photography': {
        'Hardware controls : take pictures and videos (D)',
        'Storage : modify/delete USB storage contents modify/delete SD card contents (D)',
        'Network communication : full Internet access (D)',
        'Hardware controls : record audio (D)',
        'Your location : fine (GPS) location (D)',
        'Hardware controls : control flashlight (S)',
    },
    'Communication': {
        'Your personal information : read contact data (D)',
        'Your personal information : write contact data (D)',
        'Your messages : read SMS or MMS (D)',
        'Your messages : send SMS messages (D)',
        'Services that cost you money : directly call phone numbers (D)',
        'Hardware controls : record audio (D)',
        'Phone calls : read phone state and identity (D)',
        'Network communication : full Internet access (D)',
        'Your location : coarse (network-based) location (D)',
        'Hardware controls : take pictures and videos (D)',
        'Storage : modify/delete USB storage contents modify/delete SD card contents (D)',
    },
    'Maps': {
        'Your location : fine (GPS) location (D)',
        'Your location : coarse (network-based) location (D)',
        'Network communication : full Internet access (D)',
        'Your personal information : read contact data (D)',
        'Hardware controls : record audio (D)',
    },
    'Finance': {
        'Network communication : full Internet access (D)',
        'Your personal information : read contact data (D)',
        'Your messages : read SMS or MMS (D)', # For OTPs
        'Phone calls : read phone state and identity (D)', # For device verification
    },
    'Games': {
        'Network communication : full Internet access (D)',
        'Storage : modify/delete USB storage contents modify/delete SD card contents (D)',
        'System tools : prevent device from sleeping (D)',
    },
    'Shopping': {
        'Network communication : full Internet access (D)',
        'Storage : modify/delete USB storage contents modify/delete SD card contents (D)',
        'Your location : coarse (network-based) location (D)',
        'Hardware controls : take pictures and videos (D)', # For scanning products
    }
}
def check_fraud_by_rules(category, requested_permissions):
    """
    Checks for fraud based on a deterministic rule set using full permission names.
    Returns a list of suspicious permissions.
    """
    # Use "Other" as a fallback if the category from the frontend isn't in our rules
    effective_category = category if category in ALLOWED_PERMISSIONS else "Other"
    
    if effective_category == "Other":
        # For "Other" category, we can't make a judgment, so no permissions are suspicious
        return []

    allowed = ALLOWED_PERMISSIONS[effective_category]
    suspicious_permissions = []

    for perm in requested_permissions:
        if perm not in allowed:
            # We only care about the permission name, not the category part
            permission_name = perm.split(' : ')[1]
            suspicious_permissions.append(permission_name)
            
    return suspicious_permissions

# --- NLTK Setup ---
def setup_nltk():
    """Downloads necessary NLTK data if not already present."""
    try:
        nltk.data.find('tokenizers/punkt')
        nltk.data.find('corpora/stopwords')
        nltk.data.find('corpora/wordnet')
    except:
        print("Downloading NLTK data for sentiment analysis...")
        nltk.download('punkt', quiet=True)
        nltk.download('stopwords', quiet=True)
        nltk.download('wordnet', quiet=True)
    print("NLTK data is ready.")

# --- Model Loading ---
def load_all_models():
    """Loads all ML models and returns them."""
    models = {}
    base_dir = os.path.dirname(__file__)

    # 1. Website Phishing Model
    try:
        models['web_model'] = joblib.load(os.path.join(base_dir, 'ml_model', 'model_web.joblib'))
        print("✅ Successfully loaded website phishing model.")
    except FileNotFoundError:
        print("⚠️ Warning: Website model not found.")
        models['web_model'] = None

    # 2. Android Malware Model v3
    try:
        model_path = os.path.join(base_dir, 'ml_model', 'model_app_v3.keras')
        features_path = os.path.join(base_dir, 'ml_model', 'model_app_features_v3.joblib')
        
        mobile_model = tf.keras.models.load_model(model_path, compile=False)
        features_data = joblib.load(features_path)
        
        scaler = StandardScaler()
        scaler.mean_ = features_data['scaler_mean']
        scaler.scale_ = features_data['scaler_scale']
        
        models['mobile_model_components'] = {
            'model': mobile_model,
            'scaler': scaler,
            'features': features_data['columns'],
            'optimal_threshold': features_data['optimal_threshold'],
            'scaled_columns': features_data['scaled_columns']
        }
        print("✅ Successfully loaded Android malware model v3.")
    except Exception as e:
        print(f"⚠️ Warning: Could not load the Android malware model v3. Error: {e}")
        models['mobile_model_components'] = None

    # 3. Review Sentiment Model
    try:
        models['sentiment_model'] = joblib.load(os.path.join(base_dir, 'ml_model', 'sentiment_model.joblib'))
        print("✅ Successfully loaded review sentiment model.")
    except FileNotFoundError:
        print("⚠️ Warning: Sentiment model not found.")
        models['sentiment_model'] = None
    try:
        models['tfidf_vectorizer'] = joblib.load(os.path.join(base_dir, 'ml_model', 'tfidf_vectorizer.joblib'))
        print("✅ Successfully loaded TF-IDF vectorizer.")
    except FileNotFoundError:
        print("⚠️ Warning: TF-IDF vectorizer not found.")
        models['tfidf_vectorizer'] = None
        
    return models

# --- Text Preprocessing ---
def PreProcessText(review):
    """Cleans and prepares a single review text for the sentiment model."""
    lemmatizer = WordNetLemmatizer()
    stop_words = set(stopwords.words('english'))
    stop_words.remove('not')
    tokens = word_tokenize(review.lower())
    tokens = [lemmatizer.lemmatize(word) for word in tokens if word.isalnum() and word not in stop_words]
    return ' '.join(tokens)

# --- Google Play Scraping ---
def get_app_id_from_name(app_name: str) -> str | None:
    """Searches the Play Store for an app name and returns its package ID."""
    driver = None
    try:
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--lang=en-US")
        options.add_argument("--log-level=3")
        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
        search_query = "+".join(app_name.split())
        url = f"https://play.google.com/store/search?q={search_query}&c=apps"
        driver.get(url)
        wait = WebDriverWait(driver, 10)
        app_link_element = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "a.Qfxief")))
        app_href = app_link_element.get_attribute('href')
        app_id = app_href.split('?id=')[-1]
        print(f"Found App ID for '{app_name}': {app_id}")
        return app_id
    except TimeoutException:
        print(f"Could not find an app named '{app_name}'.")
        return None
    finally:
        if driver:
            driver.quit()

def scrape_review_texts(app_id: str, num_reviews_to_scrape: int = 50) -> list:
    """Scrapes review texts for a given app ID."""
    driver = None
    try:
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--lang=en-US")
        options.add_argument("--log-level=3")
        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
        url = f"https://play.google.com/store/apps/details?id={app_id}"
        driver.get(url)
        wait = WebDriverWait(driver, 10)
        see_all_reviews_button = wait.until(EC.element_to_be_clickable((By.XPATH, '//span[contains(text(), "See all reviews")]/parent::button')))
        see_all_reviews_button.click()
        modal_dialog = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "div.fysCi")))
        print(f"Scraping review texts for {app_id}...")
        scraped_texts = []
        while len(scraped_texts) < num_reviews_to_scrape:
            last_height = driver.execute_script("return arguments[0].scrollHeight", modal_dialog)
            driver.execute_script('arguments[0].scrollTop = arguments[0].scrollHeight', modal_dialog)
            time.sleep(2)
            new_height = driver.execute_script("return arguments[0].scrollHeight", modal_dialog)
            if new_height == last_height:
                print("Reached the end of the reviews.")
                break
            soup = BeautifulSoup(driver.page_source, "html.parser")
            review_blocks = soup.find_all('div', class_='RHo1pe')
            current_texts = [block.find('div', class_='h3YV2d').text.strip() for block in review_blocks if block.find('div', class_='h3YV2d')]
            for text in current_texts:
                if text not in scraped_texts:
                    scraped_texts.append(text)
            print(f"Collected {len(scraped_texts)} unique reviews...")
        return scraped_texts[:num_reviews_to_scrape]
    except TimeoutException:
        print("A timeout occurred while scraping reviews.")
        return []
    finally:
        if driver:
            driver.quit()