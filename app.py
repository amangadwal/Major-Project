import streamlit as st
import google.generativeai as genai
import requests
import os
import hashlib
import json
from datetime import datetime

# --- USER AUTHENTICATION SYSTEM ---

def hash_password(password):
    """Hash a password for storing."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed_password):
    """Verify a stored password against one provided by user"""
    return hash_password(password) == hashed_password

def init_user_db():
    """Initialize user database in session state"""
    if 'users' not in st.session_state:
        st.session_state.users = {}
    
    # Load users from secrets if available (for persistence)
    try:
        if 'USER_DB' in st.secrets:
            st.session_state.users = json.loads(st.secrets["USER_DB"])
    except:
        pass

def save_user_db():
    """Save user database (in production, you'd use a real database)"""
    # Note: In production, use a proper database instead of secrets
    pass

def create_user(username, password, email=""):
    """Create a new user"""
    if username in st.session_state.users:
        return False, "Username already exists"
    
    st.session_state.users[username] = {
        'password_hash': hash_password(password),
        'email': email,
        'created_at': datetime.now().isoformat()
    }
    save_user_db()
    return True, "User created successfully"

def authenticate_user(username, password):
    """Authenticate a user"""
    if username not in st.session_state.users:
        return False, "User not found"
    
    if verify_password(password, st.session_state.users[username]['password_hash']):
        return True, "Login successful"
    else:
        return False, "Invalid password"

def logout_user():
    """Log out the current user"""
    st.session_state.logged_in = False
    st.session_state.current_user = None

# --- API CONFIGURATION ---

# Configure Gemini API
try:
    genai.configure(api_key=st.secrets["GEMINI_API_KEY"])
    gemini_model = genai.GenerativeModel("models/gemini-2.5-flash")
except Exception as e:
    st.error(f"Failed to configure Gemini API: {e}")
    gemini_model = None

# --- HOSPITAL SEARCH USING NOMINATIM (BEST METHOD) ---

def get_nearby_hospitals(location_query):
    """
    Fast, free search for hospitals using Nominatim (OpenStreetMap).
    No API key required.
    """
    try:
        headers = {"User-Agent": "HealthFinderApp/1.0"}

        # Direct search: "hospital near <location>"
        url = "https://nominatim.openstreetmap.org/search"
        params = {
            "q": f"hospital near {location_query}",
            "format": "json",
            "limit": 15
        }

        resp = requests.get(url, params=params, headers=headers)
        results = resp.json()

        if not results:
            return {"status": "ZERO_RESULTS", "results": []}

        hospitals = []
        for h in results:
            hospitals.append({
                "name": h.get("display_name", "Unnamed Hospital"),
                "lat": float(h["lat"]),
                "lon": float(h["lon"])
            })

        return {"status": "OK", "results": hospitals}

    except Exception as e:
        return {"status": "ERROR", "error": str(e), "results": []}

# --- GEMINI DISEASE SUGGESTION ---

def get_disease_suggestion(symptoms):
    if not gemini_model:
        return "Gemini API is not configured."

    prompt = f"""
    You are a helpful medical information assistant.
    The user reports these symptoms: "{symptoms}"

    Based on these symptoms alone, list 3–5 POSSIBLE conditions
    with a one-sentence description for each.

    END your reply with this EXACT sentence:
    "*Disclaimer:* I am an AI assistant and not a medical professional. This information is not a diagnosis. Please consult a qualified healthcare provider for medical advice."
    """

    try:
        response = gemini_model.generate_content(prompt)
        return response.text
    except Exception as e:
        return f"Error contacting Gemini API: {e}"

# --- STREAMLIT UI ---

def main_app():
    """Main application that shows after login"""
    st.set_page_config(layout="wide", page_title="Symptom Analyzer")
    
    # Header with user info and logout
    col_header1, col_header2 = st.columns([3, 1])
    with col_header1:
        st.title("🏥 Symptom & Hospital Finder")
    with col_header2:
        st.write(f"Welcome, *{st.session_state.current_user}*!")
        if st.button("Logout"):
            logout_user()
            st.rerun()
    
    st.markdown("Enter your symptoms and location to receive AI insights and nearby hospitals.")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Step 1: Describe Your Symptoms")
        symptoms_input = st.text_area("Example: fever, headache, fatigue", height=150)

        st.subheader("Step 2: Enter Your Location")
        location_input = st.text_input("City, Region, Zip Code, etc.")

        analyze_button = st.button("Analyze & Search")

    with col2:
        st.subheader("Step 3: Results")

        if analyze_button:
            if not symptoms_input:
                st.warning("Please enter your symptoms.")
            elif not location_input:
                st.warning("Please enter your location.")
            else:
                # --- GEMINI ANALYSIS ---
                with st.spinner("Analyzing symptoms with AI..."):
                    st.markdown("### 🩺 Possible Conditions")
                    disease_info = get_disease_suggestion(symptoms_input)
                    st.markdown(disease_info)

                st.divider()

                # --- HOSPITAL SEARCH ---
                with st.spinner(f"Searching for hospitals near {location_input}..."):
                    st.markdown(f"### 🏨 Hospitals Near {location_input}")

                    hospital_data = get_nearby_hospitals(location_input)

                    if hospital_data["status"] == "OK":
                        hospital_list = hospital_data["results"]

                        for i, h in enumerate(hospital_list, start=1):
                            st.markdown(f"*{i}. {h['name']}*")

                        # Map view
                        map_points = [{"lat": h["lat"], "lon": h["lon"]} for h in hospital_list]
                        st.map(map_points)

                    elif hospital_data["status"] == "ZERO_RESULTS":
                        st.warning("No hospitals found for that location.")
                    else:
                        st.error(f"Error fetching hospital data: {hospital_data.get('error', 'Unknown error')}")

def login_signup_page():
    """Login and signup page"""
    st.set_page_config(layout="centered", page_title="Login - Symptom Analyzer")
    
    st.title("🏥 Symptom & Hospital Finder")
    st.markdown("### Please login or sign up to continue")
    
    tab1, tab2 = st.tabs(["Login", "Sign Up"])
    
    with tab1:
        st.subheader("Login to Your Account")
        login_username = st.text_input("Username", key="login_username")
        login_password = st.text_input("Password", type="password", key="login_password")
        
        if st.button("Login", key="login_btn"):
            if login_username and login_password:
                success, message = authenticate_user(login_username, login_password)
                if success:
                    st.session_state.logged_in = True
                    st.session_state.current_user = login_username
                    st.success("Login successful!")
                    st.rerun()
                else:
                    st.error(message)
            else:
                st.warning("Please enter both username and password")
    
    with tab2:
        st.subheader("Create New Account")
        signup_username = st.text_input("Choose Username", key="signup_username")
        signup_email = st.text_input("Email (optional)", key="signup_email")
        signup_password = st.text_input("Choose Password", type="password", key="signup_password")
        signup_confirm = st.text_input("Confirm Password", type="password", key="signup_confirm")
        
        if st.button("Create Account", key="signup_btn"):
            if not signup_username or not signup_password:
                st.warning("Please enter both username and password")
            elif signup_password != signup_confirm:
                st.error("Passwords do not match")
            elif len(signup_password) < 4:
                st.warning("Password should be at least 4 characters long")
            else:
                success, message = create_user(signup_username, signup_password, signup_email)
                if success:
                    st.success("Account created successfully! Please login.")
                else:
                    st.error(message)

# --- INITIALIZE APP ---

# Initialize user database
init_user_db()

# Initialize session state for authentication
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None

# Route to appropriate page
if st.session_state.logged_in:
    main_app()
else:
    login_signup_page()