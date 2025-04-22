import streamlit as st
import json
import os
import time
import hashlib
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac
from cryptography.fernet import Fernet

DATA_FILE = "data.json"
LOCKOUT_DURATION = 60  # seconds

# Load stored data from file
def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r") as f:
                content = f.read().strip()
                if content:  # Check if file is not empty
                    return json.loads(content)
                return {}  # Return empty dict for empty file
        except (json.JSONDecodeError, IOError):
            return {}  # Return empty dict for invalid JSON or read errors
    return {}

# Save data to file
def save_data(data):
    try:
        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=4)  # Ensure valid JSON with indentation
    except IOError:
        st.error("❌ Error saving data to file.")

# Generate encryption key from passkey
def generate_key(passkey):
    salt = b'some_static_salt'  # Use unique salt per user in real systems
    key = pbkdf2_hmac('sha256', passkey.encode(), salt, 100000, dklen=32)
    return urlsafe_b64encode(key)

# Encrypt data
def encrypt_data(text, passkey):
    try:
        cipher = Fernet(generate_key(passkey))
        return cipher.encrypt(text.encode()).decode()
    except Exception:
        st.error("❌ Encryption failed. Please check your passkey.")
        return None

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    try:
        cipher = Fernet(generate_key(passkey))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except Exception:
        return None

# Hash password for user login
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# --- Streamlit App Logic Starts Here ---

st.set_page_config(
    page_title="Secure Data Vault",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply professional styling
st.markdown("""
    <style>
    .main {
        background-color: #f8f9fa;
        padding: 30px;
        border-radius: 12px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
    .stButton>button {
        background-color: #0057b3;
        color: white;
        border-radius: 8px;
        padding: 12px 24px;
        font-weight: bold;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #003d82;
        transform: translateY(-2px);
    }
    .sidebar .sidebar-content {
        background-color: #e9ecef;
        padding: 20px;
        border-radius: 8px;
    }
    h1, h2, h3 {
        color: #1a3c6e;
        font-family: 'Helvetica Neue', sans-serif;
    }
    .info-box {
        background-color: #e7f3ff;
        padding: 20px;
        border-radius: 8px;
        border-left: 6px solid #0057b3;
        margin-bottom: 20px;
        transition: all 0.3s ease;
    }
    .info-box:hover {
        transform: translateX(5px);
    }
    .stTextInput>div>input, .stTextArea>div>textarea {
        border-radius: 8px;
        border: 1px solid #ced4da;
        padding: 10px;
    }
    .stAlert {
        border-radius: 8px;
        padding: 15px;
    }
    .username-display {
        font-weight: bold;
        color: #1a3c6e;
        margin-bottom: 20px;
        padding: 10px;
        background-color: #ffffff;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    </style>
""", unsafe_allow_html=True)

st.title("🔒 Secure Data Vault")

# Initialize session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.locked_until = 0
    st.session_state.failed_attempts = 0
    st.session_state.selected_page = "Register" if not load_data() else "Home"

# Sidebar: Display username if logged in
if st.session_state.logged_in and st.session_state.username:
    st.sidebar.markdown(
        f"<div class='username-display'>👤 Logged in as: {st.session_state.username}</div>",
        unsafe_allow_html=True
    )

# Sidebar menu
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
if st.session_state.logged_in:
    menu.append("Logout")

# Use selected_page to set the initial value of the selectbox
choice = st.sidebar.radio(
    "Navigation",
    menu,
    format_func=lambda x: f"📌 {x}",
    key="nav_menu",
    index=menu.index(st.session_state.selected_page) if st.session_state.selected_page in menu else 0
)

data = load_data()

# Handle logout with confirmation
if choice == "Logout":
    st.subheader("🚪 Logout")
    st.markdown("<div class='info-box'>Are you sure you want to log out?</div>", unsafe_allow_html=True)
    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("Confirm Logout"):
            st.session_state.logged_in = False
            st.session_state.username = ""
            st.session_state.failed_attempts = 0
            st.session_state.selected_page = "Home"
            st.success("✅ Successfully logged out!")
            choice = "Home"
    with col2:
        if st.button("Cancel"):
            st.session_state.selected_page = "Home"
            choice = "Home"

if choice == "Home":
    st.session_state.selected_page = "Home"
    st.subheader("🏠 Welcome to Secure Data Vault")
    st.markdown("""
    <div class="info-box">
        <h3>Safeguard Your Sensitive Information</h3>
        <p>Secure Data Vault offers a robust platform to encrypt, store, and retrieve your data with industry-standard encryption. Use the sidebar to register, log in, or manage your data securely.</p>
    </div>
    """, unsafe_allow_html=True)
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("### Key Features")
        st.write("- 🔒 AES26 write 🔑 Secure passkey-based data protection")
        st.write("- 🛡️ Account lockout after failed attempts")
    with col2:
        st.markdown("### Get Started")
        st.write("1. Create an account")
        st.write("2. Log in securely")
        st.write("3. Encrypt and manage your data")

elif choice == "Register":
    st.session_state.selected_page = "Register"
    st.subheader("📝 Register New Account")
    new_user = st.text_input("Username", placeholder="Enter your username (min 4 characters)")
    new_pass = st.text_input("Password", type="password", placeholder="Enter your password (min 8 characters)")
    if st.button("Register"):
        if not new_user or len(new_user) < 4:
            st.error("❌ Username must be at least 4 characters.")
        elif not new_pass or len(new_pass) < 8:
            st.error("❌ Password must be at least 8 characters.")
        elif new_user in data:
            st.error("❌ Username already exists.")
        else:
            data[new_user] = {
                "password": hash_password(new_pass),
                "data": "",
            }
            save_data(data)
            st.success("✅ Account created successfully! Please log in.")
            st.session_state.selected_page = "Login"
            choice = "Login"

elif choice == "Login":
    st.session_state.selected_page = "Login"
    st.subheader("🔑 Login to Your Account")
    user = st.text_input("Username", placeholder="Enter your username")
    password = st.text_input("Password", type="password", placeholder="Enter your password")
    if st.button("Login"):
        current_time = time.time()
        if current_time < st.session_state.locked_until:
            remaining = int(st.session_state.locked_until - current_time)
            st.warning(f"⏳ Account locked! Try again in {remaining} seconds.")
        elif not user or not password:
            st.error("❌ Please fill in all fields.")
        elif user in data and data[user]["password"] == hash_password(password):
            st.session_state.logged_in = True
            st.session_state.username = user
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome back, {user}!")
            st.session_state.selected_page = "Home"
            choice = "Home"
        else:
            st.session_state.failed_attempts += 1
            st.error("❌ Invalid username or password.")
            if st.session_state.failed_attempts >= 3:
                st.session_state.locked_until = current_time + LOCKOUT_DURATION
                st.warning("⛔ Too many attempts! Account locked for 60 seconds.")

elif choice == "Store Data":
    st.session_state.selected_page = "Store Data"
    if st.session_state.logged_in:
        st.subheader("💾 Store Encrypted Data")
        user_input = st.text_area("Enter text to encrypt", placeholder="Type your sensitive data here...")
        user_passkey = st.text_input("Enter a secret passkey", type="password", placeholder="Enter your passkey (min 6 characters)")
        if st.button("Encrypt & Save"):
            if not user_input:
                st.error("❌ Please enter data to encrypt.")
            elif not user_passkey or len(user_passkey) < 6:
                st.error("❌ Passkey must be at least 6 characters.")
            else:
                encrypted = encrypt_data(user_input, user_passkey)
                if encrypted:  # Check if encryption succeeded
                    data[st.session_state.username]["data"] = encrypted
                    save_data(data)
                    st.success("✅ Data encrypted and saved successfully!")
    else:
        st.warning("⚠️ Please log in to store data.")

elif choice == "Retrieve Data":
    st.session_state.selected_page = "Retrieve Data"
    if st.session_state.logged_in:
        st.subheader("🔍 Retrieve Encrypted Data")
        user_passkey = st.text_input("Enter your secret passkey", type="password", placeholder="Enter your passkey")
        if st.button("Decrypt"):
            if not user_passkey:
                st.error("❌ Please enter a passkey.")
            else:
                encrypted_text = data[st.session_state.username].get("data", "")
                if encrypted_text:
                    decrypted = decrypt_data(encrypted_text, user_passkey)
                    if decrypted:
                        st.success(f"✅ Decrypted Data: {decrypted}")
                    else:
                        st.error("❌ Incorrect passkey.")
                else:
                    st.info("ℹ️ No data stored yet.")
    else:
        st.warning("⚠️ Please log in to retrieve data.")