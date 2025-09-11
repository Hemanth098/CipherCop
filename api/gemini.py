# -*- coding: utf-8 -*-
import os
import re
import textwrap
import unicodedata
from dotenv import load_dotenv
import google.generativeai as genai

key="AIzaSyDDXzJILfyL5mJRrfRkkD1FOn1g6DMNRl8"
# -----------------------------------------------------------
# 1. Load API Key
# -----------------------------------------------------------
def load_gemini_api():
    """Loads Gemini API key from environment variables."""
    load_dotenv()
    if not key:
        print("Error: GEMINI_API_KEY not found in environment variables.")
        exit()
    genai.configure(api_key=key)


# -----------------------------------------------------------
# 2. Initialize Gemini Model
# -----------------------------------------------------------
def get_gemini_model():
    """Returns a configured Gemini model instance."""
    model = genai.GenerativeModel(
        'gemini-2.0-flash',
        generation_config={
            "temperature": 0.2,         # lower = more consistent
            "max_output_tokens": 512    # limit tokens
        }
    )
    return model


# -----------------------------------------------------------
# 3. System Prompt
# -----------------------------------------------------------
system_prompt = """
You are an expert cybersecurity analyst with deep knowledge of phishing, scam websites, malicious online activity, 
and advanced attacks such as homograph (IDN/holographic) domain spoofing.

Your role is to carefully analyze the content of a given website (including its text, structure, metadata, and links). 
Determine whether the website is a phishing attempt or legitimate. 

Follow these rules strictly:
- Base your reasoning on typical phishing patterns (suspicious login forms, misleading links, brand impersonation, urgent warnings).
- Always check for homograph/holographic URLs where different Unicode scripts (e.g., Cyrillic, Greek) are used to mimic real domains.
- Always explain the reasoning in concise points.
- Be objective: if uncertain, classify as "suspicious" instead of giving a false "safe" verdict.

Respond ONLY in this parameterized format (do not add explanations outside this format):

verdict=<phishing or legitimate or suspicious>
risk_level=<high, medium, or safe>
confidence=<high, medium, low>
reasons=<comma-separated brief reasons>
evidence=<comma-separated concrete evidence snippets from the website>
"""


# -----------------------------------------------------------
# 4. Homograph Detector
# -----------------------------------------------------------
def detect_homograph(url: str) -> bool:
    """
    Detects potential homograph (holographic) attacks in a URL 
    by checking for mixed Unicode scripts in the domain name.
    """
    try:
        domain_match = re.findall(r"://([^/]+)/?", url)
        if not domain_match:
            return False
        domain = domain_match[0]

        scripts = set()
        for char in domain:
            try:
                name = unicodedata.name(char)
                if "CYRILLIC" in name:
                    scripts.add("CYRILLIC")
                elif "GREEK" in name:
                    scripts.add("GREEK")
                elif "LATIN" in name:
                    scripts.add("LATIN")
            except ValueError:
                continue

        # Suspicious if multiple scripts are mixed
        return len(scripts) > 1
    except Exception:
        return False


# -----------------------------------------------------------
# 5. Gemini Analyzer
# -----------------------------------------------------------
def gemini_analyze(website_content: str, model):
    """
    Analyzes website content for phishing using the configured Gemini model.
    Includes robust error handling for API calls and homograph detection.
    """
    try:
        # Check for links in the content
        urls = re.findall(r'href=[\'"]?([^\'" >]+)', website_content)
        homograph_flag = False
        for url in urls:
            if detect_homograph(url):
                homograph_flag = True
                website_content += f"\n\n[Warning: Suspicious homograph URL detected: {url}]"

        # Generate response from Gemini
        response = model.generate_content(
            system_prompt + "\n\nWebsite Content:\n" + textwrap.dedent(website_content),
            stream=False
        )

        # Check if blocked
        if hasattr(response, "prompt_feedback") and response.prompt_feedback.block_reason:
            print(f"⚠️ Content was blocked: {response.prompt_feedback.block_reason.name}")
            return "Error: Content blocked"

        clean_output = response.text.replace("*", "").strip()

        # Add homograph flag for clarity
        if homograph_flag:
            clean_output += "\n[Homograph detection triggered]"

        return clean_output

    except genai.types.StopCandidateException as e:
        print(f"⚠️ Generation stopped prematurely: {e}")
        return "Error: Generation stopped"
    except Exception as e:
        print(f"⚠️ An error occurred: {e}")
        return "Error: API call failed"


# -----------------------------------------------------------
# 6. Example Usage
# -----------------------------------------------------------
def parse_analysis_to_list(output_string: str) -> list:
    """Parses the Gemini response string into a list of key-value tuples."""
    if output_string.startswith("Error:"):
        return [("error", output_string)]

    result_list = []
    for line in output_string.strip().split("\n"):
        if "=" in line:
            parts = line.split("=", 1)  # split only once
            if len(parts) == 2:
                key, value = parts
                result_list.append((key.strip(), value.strip()))
    return result_list

def calculate_fraud_percentage(parsed: dict) -> int:
    """Converts risk_level and confidence into fraud percentage."""
    mapping = {
        ("high", "high"): 95,
        ("high", "medium"): 80,
        ("high", "low"): 65,
        ("medium", "high"): 55,
        ("medium", "medium"): 40,
        ("medium", "low"): 25,
        ("safe", "high"): 10,
        ("safe", "medium"): 5,
        ("safe", "low"): 2,
    }

    risk_level = parsed.get("risk_level", "").lower()
    confidence = parsed.get("confidence", "").lower()

    return mapping.get((risk_level, confidence), 50)  # default fallback 50
  # default fallback 50
