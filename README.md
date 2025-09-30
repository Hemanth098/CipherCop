# CipherCop: AI-Powered Security Analysis Tool 🛡️

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Python Version](https://img.shields.io/badge/python-3.9+-blue)
![Framework](https://img.shields.io/badge/framework-Django-darkgreen)
![License](https://img.shields.io/badge/license-MIT-informational)

CipherCop is a comprehensive security tool that analyzes websites, mobile apps, and APK files to identify potential phishing, malware, and other security risks. It employs a powerful hybrid approach, integrating AI analysis, custom machine learning models, and real-time data from APIs like VirusTotal to deliver a robust threat assessment.

---

## 🏛️ System Architecture

The application is built on a monolithic Django backend that serves RESTful APIs. Its core relies on a hybrid analysis engine that combines generative AI, pre-trained machine learning models, and external APIs for comprehensive threat detection.

![CipherCop Architecture](./path/to/your/architecture_diagram.png)

---

## ✨ Core Features

CipherCop provides three main analysis modules accessible through its API.

### 1. Website Security Analysis
* **Hybrid Threat Detection**: Uses a dual-pass system. It first queries **Google's Gemini AI** for a rapid assessment. If confidence is low, it performs a deep analysis using a custom **Machine Learning model** trained on over 80 lexical and domain-based features.
* **Real-Time Data Enrichment**: Integrates **WHOIS** lookups for domain age and registration details and queries the **Open PageRank API** to factor in domain authority.
* **Comprehensive Reporting**: Delivers a final fraud score and a verdict of "Legitimate," "Suspicious," or "Phishing."

### 2. APK File Analysis
* **Dual-Vector Analysis**: Checks APK files along two vectors: safety and authenticity.
    * **Safety (Malware Detection)**: A machine learning model analyzes the permissions requested in the APK's manifest to predict if it's benign or malicious.
    * **Authenticity (Reputation Check)**: The file's **SHA256 hash** is checked against the **VirusTotal API**. If the file has been flagged by security vendors, it's marked as "Modified"; otherwise, it's considered "Official."
* **Clear Verdicts**: Provides a combined category like "Safe, Official App" or "Malicious Mod APK."

### 3. Google Play Store App Analysis
* **Public Sentiment Analysis**: Scrapes user reviews for a given app from the Play Store and uses a **sentiment analysis model** to gauge public opinion and trust.
* **Rule-Based Permission Checking**: Flags potentially dangerous or unnecessary permissions based on the app's declared category (e.g., a calculator app asking for contact access).
* **Hybrid Risk Scoring**: Combines sentiment score and permission risk to categorize apps as "Low-Risk," "Medium-Risk," or "High-Risk."

### 4. Browser Extension
* **Real-Time Protection**: A companion browser extension allows users to analyze their current webpage with a single click.
* **Seamless Integration**: It sends the active URL to the backend and displays the security verdict directly within the browser, providing an immediate layer of defense against phishing.

---

## 💻 Tech Stack

* **Backend**: Django, Django REST Framework
* **Machine Learning**: TensorFlow, Scikit-learn, Pandas, NLTK
* **Data Parsing**: `pyaxmlparser` (for APKs), BeautifulSoup (for scraping)
* **APIs & Services**: Google Gemini, VirusTotal, Open PageRank
* **Database**: SQLite3 (default, configurable)
* **Frontend**: HTML, CSS, JavaScript (for the web interface)

---

## 🚀 Getting Started

Follow these instructions to set up the project locally.

### Prerequisites
* Python 3.9+
* pip package manager
* Git

### Installation
1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/Hemanth098/CipherCop.git](https://github.com/Hemanth098/CipherCop.git)
    cd CipherCop
    ```
2.  **Create and activate a virtual environment:**
    ```bash
    # For Windows
    python -m venv venv
    .\venv\Scripts\activate

    # For macOS/Linux
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  **Install the required packages:**
    ```bash
    pip install -r requirements.txt
    ```
4.  **Set up environment variables:**
    Create a `.env` file in the project's root directory and add your API keys. You can use an `.env.example` file as a template:
    ```ini
    # .env
    GEMINI_API_KEY="YOUR_GOOGLE_GEMINI_API_KEY"
    VIRUSTOTAL_API_KEY="YOUR_VIRUSTOTAL_API_KEY"
    DOMCOP_API_KEY="YOUR_OPEN_PAGERANK_API_KEY"
    ```
5.  **Run Django migrations:**
    ```bash
    python manage.py migrate
    ```
6.  **Start the development server:**
    ```bash
    python manage.py runserver
    ```
    The API will now be running at `http://127.0.0.1:8000`.

---

## 🔌 API Endpoints

The system exposes the following `POST` endpoints for analysis.

### 1. Analyze Website
* **Endpoint**: `/analyze_website`
* **Description**: Analyzes a URL for phishing risks.
* **Request Body**:
    ```json
    {
      "url": "[http://example-phishing-site.com](http://example-phishing-site.com)"
    }
    ```
* **Success Response**:
    ```json
    {
        "url": "[http://example-phishing-site.com](http://example-phishing-site.com)",
        "fraudScore": 95,
        "category": "Phishing",
        "analysisDetails": "...",
        "timestamp": "2025-09-30T18:00:00Z"
    }
    ```

### 2. Analyze APK File
* **Endpoint**: `/analyze_apk`
* **Description**: Analyzes an uploaded `.apk` file for malware and authenticity. Use a `multipart/form-data` request.
* **Request (`curl` example)**:
    ```bash
    curl -X POST -F "apk_file=@/path/to/your/app.apk" [http://127.0.0.1:8000/analyze_apk](http://127.0.0.1:8000/analyze_apk)
    ```
* **Success Response**:
    ```json
    {
        "url": "app.apk",
        "category": "Malicious Mod APK",
        "analysisDetails": "This app is a modified version AND our model detected malicious permission patterns...",
        "safetyPrediction": "Malicious",
        "authenticityPrediction": "Modified",
        "timestamp": "2025-09-30T18:05:00Z"
    }
    ```

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue to discuss any changes.

1.  Fork the repository.
2.  Create your feature branch (`git checkout -b feature/AmazingFeature`).
3.  Commit your changes (`git commit -m 'Add some AmazingFeature'`).
4.  Push to the branch (`git push origin feature/AmazingFeature`).
5.  Open a Pull Request.

---

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for more details.
