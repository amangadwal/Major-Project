import google.generativeai as genai
import toml
import os

print("--- Starting Gemini API Test ---")

try:
    # Load API key from .streamlit/secrets.toml
    secrets_path = os.path.join(os.path.dirname(__file__), '.streamlit', 'secrets.toml')
    secrets = toml.load(secrets_path)
    api_key = secrets["GEMINI_API_KEY"]

    # Configure Gemini
    genai.configure(api_key=api_key)
    print("[SUCCESS] API Key loaded and configured")

    # --- List available models ---
    print("\n[AVAILABLE MODELS]")
    for m in genai.list_models():
        print(" -", m.name)

    # Pick a model that actually exists
    model_name = "gemini-2.5-flash"   # you may need to change this after listing
    print(f"\n[INFO] Using model: {model_name}")

    model = genai.GenerativeModel(model_name)
    response = model.generate_content("Hello, this is a test.")

    print("\n--- GEMINI API TEST SUCCESSFUL ---")
    print(f"API Response:\n{response.text}")
    print("----------------------------------")

except FileNotFoundError:
    print("[ERROR] secrets.toml not found.")
except Exception as e:
    print("\n--- GEMINI API TEST FAILED ---")
    print("Error:", e)
    print("------------------------------")
