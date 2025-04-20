import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ------------------------------
# Session Initialization
# ------------------------------
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "key" not in st.session_state:
    st.session_state.key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.key)

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# ------------------------------
# Helper Functions
# ------------------------------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, hashed_passkey):
    for record in st.session_state.stored_data.values():
        if record["passkey"] == hashed_passkey and record["encrypted_text"] == encrypted_text:
            st.session_state.failed_attempts = 0
            return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# ------------------------------
# Streamlit App UI
# ------------------------------
st.set_page_config(page_title="Secure Encryption", page_icon="🔐")
st.markdown("""
    <style>
    .main { background-color: #f0f4f8; }
    .stButton>button { background-color: #4A90E2; color: white; border-radius: 8px; padding: 0.5em 1.5em; }
    .stTextInput>div>div>input { border-radius: 6px; }
    .stTextArea>div>textarea { border-radius: 6px; }
    </style>
""", unsafe_allow_html=True)

st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.header("🏠 Welcome")
    st.write("Safely **store and retrieve encrypted data** using a secure passkey. All operations are handled in-memory.")

elif choice == "Store Data":
    st.header("📥 Store Data")
    with st.form("store_form"):
        data_key = st.text_input("Enter a unique key (e.g. 'user1')")
        user_data = st.text_area("Enter Data to Encrypt")
        passkey = st.text_input("Enter a Passkey", type="password")
        submitted = st.form_submit_button("Encrypt & Save")

        if submitted:
            if data_key and user_data and passkey:
                hashed = hash_passkey(passkey)
                encrypted = encrypt_data(user_data)
                st.session_state.stored_data[data_key] = {
                    "encrypted_text": encrypted,
                    "passkey": hashed
                }
                st.success("✅ Data stored successfully.")
                st.code(encrypted, language="text")
            else:
                st.error("⚠️ Please fill all the fields.")

elif choice == "Retrieve Data":
    st.header("🔓 Retrieve Data")
    with st.form("retrieve_form"):
        data_key = st.text_input("Enter the key (e.g. 'user1')")
        passkey = st.text_input("Enter Passkey", type="password")
        submitted = st.form_submit_button("Decrypt")

        if submitted:
            if data_key and passkey:
                if data_key in st.session_state.stored_data:
                    encrypted = st.session_state.stored_data[data_key]["encrypted_text"]
                    hashed = hash_passkey(passkey)
                    result = decrypt_data(encrypted, hashed)

                    if result:
                        st.success("✅ Decrypted Data:")
                        st.code(result)
                    else:
                        remaining = 3 - st.session_state.failed_attempts
                        st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")

                        if st.session_state.failed_attempts >= 3:
                            st.warning("🔒 Too many attempts. Redirecting to Login.")
                            st.experimental_rerun()
                else:
                    st.error("⚠️ No data found for this key.")
            else:
                st.error("⚠️ All fields are required.")

elif choice == "Login":
    st.header("🔑 Login Required")
    login_pass = st.text_input("Enter Admin Password", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect admin password.")

# Footer
st.caption("Developed by Asim • GIAIC Python Project")
