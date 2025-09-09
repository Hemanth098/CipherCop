import time
import re
import os
import joblib
import numpy as np
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from nltk.tokenize import word_tokenize
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from bs4 import BeautifulSoup

# --- Part 1: Load the Saved ML Model and Preprocessing Functions ---

# Function to download NLTK data if not present
def setup_nltk():
    """Downloads necessary NLTK data."""
    try:
        nltk.data.find('tokenizers/punkt')
        nltk.data.find('corpora/stopwords')
        nltk.data.find('corpora/wordnet')
    except:
        print("Downloading NLTK data...")
        nltk.download('punkt', quiet=True)
        nltk.download('stopwords', quiet=True)
        nltk.download('wordnet', quiet=True)
    print("NLTK data is ready.")

# Pre-processing function from your notebook
def PreProcessText(review):
    """Cleans and prepares a single review text for the model."""
    lemmatizer = WordNetLemmatizer()
    stop_words = set(stopwords.words('english'))
    stop_words.remove('not')
    
    tokens = word_tokenize(review.lower())
    tokens = [lemmatizer.lemmatize(word) for word in tokens if word.isalnum() and word not in stop_words]
    return ' '.join(tokens)

# Function to load the saved model and vectorizer
def load_model():
    """Loads the serialized vectorizer and model from disk."""
    try:
        vectorizer = joblib.load('./api/ml_model/tfidf_vectorizer.joblib')
        model = joblib.load('./api/ml_model/sentiment_model.joblib')
        print("✅ Model and vectorizer loaded successfully.")
        return vectorizer, model
    except FileNotFoundError:
        print("❌ Error: Model or vectorizer files not found.")
        print("Please make sure 'tfidf_vectorizer.joblib' and 'sentiment_model.joblib' are in the same directory as this script.")
        return None, None

# --- Part 2: Web Scraping Functions (from previous script) ---

def get_app_id_from_name(app_name: str) -> str | None:
    # (This function is the same as the previous version)
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

def scrape_review_texts(app_id: str, num_reviews_to_scrape: int = 100) -> list:
    # (This function is the same as the previous version)
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
            current_texts_on_page = [block.find('div', class_='h3YV2d').text.strip() for block in review_blocks if block.find('div', class_='h3YV2d')]
            for text in current_texts_on_page:
                if text not in scraped_texts:
                    scraped_texts.append(text)
            print(f"Collected {len(scraped_texts)} unique review texts so far...")
        return scraped_texts[:num_reviews_to_scrape]
    except TimeoutException:
        print("A timeout occurred while scraping.")
        return []
    finally:
        if driver:
            driver.quit()

# --- Part 3: Main Execution ---

if __name__ == "__main__":
    # Setup and load resources
    setup_nltk()
    vectorizer, model = load_model()

    if vectorizer is None or model is None:
        # Exit if the model files couldn't be loaded
        exit()

    # Get user input for the app to analyze
    app_name_input = input("Enter the name of the app you want to analyze: ")
    
    # Step 1: Find app ID and scrape reviews
    found_app_id = get_app_id_from_name(app_name_input)
    if found_app_id:
        review_texts = scrape_review_texts(found_app_id, 100)
        
        if review_texts:
            print(f"\n✅ Successfully scraped {len(review_texts)} reviews.")
            
            # Step 2: Preprocess the scraped reviews
            processed_reviews = [PreProcessText(review) for review in review_texts]
            
            # Step 3: Use the loaded model to predict sentiment
            predictions = model.predict(vectorizer.transform(processed_reviews))
            
            # Step 4: Convert predictions to numbers and calculate the mean
            numerical_predictions = [1 if p == 'positive' else 0 for p in predictions]
            mean_sentiment_score = np.mean(numerical_predictions)
            
            # Step 5: Display the final result
            print("\n--- SENTIMENT ANALYSIS RESULTS ---")
            print(f"Positive Reviews: {np.sum(numerical_predictions)}/{len(predictions)}")
            print(f"Negative Reviews: {len(predictions) - np.sum(numerical_predictions)}/{len(predictions)}")
            print(f"\nOverall Sentiment Score: {mean_sentiment_score:.2f}")
            
            if mean_sentiment_score > 0.65:
                print("Verdict: The app has a Generally Positive sentiment based on recent reviews. 👍")
            elif mean_sentiment_score > 0.45:
                print("Verdict: The app has a Mixed sentiment based on recent reviews. 🤷")
            else:
                print("Verdict: The app has a Generally Negative sentiment. This could indicate a fraudulent or low-quality app. 👎")

        else:
            print("\n❌ Could not scrape any reviews to analyze.")