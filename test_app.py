import os
import joblib
import numpy as np
from pyaxmlparser import APK
import warnings
import hashlib
import requests
import json

warnings.filterwarnings('ignore')

# --- Part 1: Helper Functions ---

def extract_permissions(apk_path):
    """
    Extracts all <uses-permission> tags from an APK's AndroidManifest.xml.
    """
    if not os.path.exists(apk_path):
        print(f"❌ Error: File not found at '{apk_path}'")
        return None
    try:
        apk = APK(apk_path)
        permissions = apk.permissions
        return permissions
    except Exception as e:
        print(f"❌ Error processing APK: {e}")
        return None

def create_feature_vector(permissions, all_features):
    """
    Creates a numerical feature vector from a list of permissions.
    """
    feature_vector = np.zeros(len(all_features))
    feature_index = {feature: i for i, feature in enumerate(all_features)}
    for p in permissions:
        if p in feature_index:
            feature_vector[feature_index[p]] = 1
    return feature_vector.reshape(1, -1)

def get_file_hash(file_path):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# --- Part 2: Main Prediction Pipeline ---

def predict_apk_authenticity_and_safety(apk_path):
    """
    Analyzes an APK for both authenticity (official vs. mod) and safety (malware vs. benign).
    """
    print("-" * 50)
    print(f"🔍 Analyzing APK: {os.path.basename(apk_path)}")

    # ❗️ IMPORTANT: Paste your free VirusTotal API key here
    VT_API_KEY = "bfff6b4bcd78a175a3846660095d1057f4b434188562ef059ef0b5478d2f1b50"

    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        print("\n❌ FATAL ERROR: Please add your VirusTotal API key to the script.")
        return

    # Step 1: Load the trained ML model and preprocessors
    try:
        model = joblib.load('best_malware_model.joblib')
        selector = joblib.load('feature_selector.joblib')
        encoder = joblib.load('label_encoder.joblib')
        feature_names = joblib.load('feature_names.joblib')
        print("✅ ML Model and preprocessors loaded successfully.")
    except FileNotFoundError:
        print("❌ Error: Model files not found. Ensure they are in the same directory.")
        return

    # Step 2: Perform Safety Check (using your ML model)
    permissions = extract_permissions(apk_path)
    if permissions is None:
        return # Stop if there was an error reading the APK

    print(f"ℹ️  Found {len(permissions)} permissions in the APK.")
    
    feature_vector = create_feature_vector(permissions, feature_names)
    vector_selected = selector.transform(feature_vector)
    prediction_encoded = model.predict(vector_selected)
    safety_prediction = encoder.inverse_transform(prediction_encoded)[0]
    print(f"✅ Safety Check Complete. Prediction: {safety_prediction}")

    # Step 3: Perform Authenticity & Reputation Check (using VirusTotal API)
    print("⏳ Performing Reputation Check with VirusTotal...")
    file_hash = get_file_hash(apk_path)
    headers = {'x-apikey': VT_API_KEY}
    vt_url = f'https://www.virustotal.com/api/v3/files/{file_hash}'

    # Default to "Unknown" until we get a definitive answer from the API
    authenticity_prediction = "Unknown" 
    vt_details = "Could not verify with VirusTotal. Treat as an unverified application."

    try:
        response = requests.get(vt_url, headers=headers)
        if response.status_code == 200:
            data = response.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            
            # A more robust check: Is the file flagged by any security vendors?
            if malicious_count > 0 or suspicious_count > 0:
                authenticity_prediction = "Potentially Unwanted / Modified"
                vt_details = (f"VirusTotal reports {malicious_count} malicious and "
                            f"{suspicious_count} suspicious detections. High risk.")
            else:
                # If there are no malicious flags, we can have higher confidence it's official/unaltered.
                authenticity_prediction = "Official / Clean"
                vt_details = "VirusTotal analysis found no malicious detections, suggesting this is a clean, official application."
                
        # Handle the case where the file has never been scanned by VirusTotal
        elif response.status_code == 404:
            authenticity_prediction = "Unknown"
            vt_details = "This file has not been seen by VirusTotal before. Authenticity cannot be confirmed."
        else:
            vt_details = f"VirusTotal API responded with status {response.status_code}. Authenticity could not be confirmed."
    except Exception as e:
        print(f"❌ VirusTotal API Error: {e}")
        vt_details = "An error occurred while contacting the VirusTotal API."

    print(f"✅ Reputation Check Complete. Prediction: {authenticity_prediction}")

    # Step 4: Combine Results into a Final Verdict
    is_safe_ml = (safety_prediction == 'Benign')
    is_clean_vt = (authenticity_prediction == "Official / Clean")

    print("\n" + "="*25 + " FINAL VERDICT " + "="*25)

    if is_clean_vt and is_safe_ml:
        print("🏆 Category: Likely Safe & Official App")
        print("🛡️  Details: Both VirusTotal and the ML model found no signs of malicious activity. Appears to be safe.")
    elif not is_clean_vt and not is_safe_ml:
        print("🚨 Category: High-Risk Malicious App")
        print("❗️ Details: The app is flagged as malicious by VirusTotal AND our model detected malicious permission patterns. Highest risk.")
    elif not is_clean_vt and is_safe_ml:
        print("⚠️  Category: Potentially Unwanted App (PUA)")
        print("❗️ Details: While our permission model didn't find malware, VirusTotal vendors detected suspicious activity. This could be a Mod or adware. Use with extreme caution.")
    else: # is_clean_vt and not is_safe_ml
        print("🤔 Category: Suspicious Permissions Detected")
        print("❗️ Details: VirusTotal found no malware, but our ML model detected a permission pattern commonly associated with malicious apps. This could be a new threat or an aggressive app. Caution advised.")

    print(f"\n- Reputation determined via VirusTotal: {authenticity_prediction}")
    print(f"- Safety determined via ML Model: {safety_prediction}")
    print(f"- VirusTotal Details: {vt_details}")
    print("="*65)

# --- Example Usage ---
if __name__ == "__main__":
    # ❗️ IMPORTANT: Replace this with the actual path to your APK file.
    path_to_apk = "C:/Users/prane/Downloads/legal.apk" 

    # Run the new, combined prediction function
    predict_apk_authenticity_and_safety(path_to_apk)