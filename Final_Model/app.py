# -*- coding: utf-8 -*-
import streamlit as st
import joblib
import time

from xgboost import XGBClassifier
file_path = "./Final_Model/deteksi_phishing.py"
model_path = "./Final_Model/DOFA-XGBoost_model.json"

from deteksi_phishing import extract_features, predict_from_url

# Membuat objek model
model_2 = XGBClassifier()
# Memuat model dari file JSON
model_2.load_model(model_path)

def reset_form():
    """Reset input URL."""
    st.session_state.url = ""

def show_title(text, color="#2e6c80"):
    """Menampilkan judul dengan styling yang konsisten."""
    st.markdown(f"<h1 style='text-align: center; color: {color};'>{text}</h1>", unsafe_allow_html=True)

def show_description(text):
    """Menampilkan deskripsi dengan styling yang konsisten."""
    st.markdown(f"<div style='text-align: center; padding: 20px;'>{text}</div>", unsafe_allow_html=True)

def show_result(url, prediction_result):
    """Menampilkan hasil analisis URL."""
    result_html = f"""
    <div style="border-radius: 10px; border: 1px solid #ddd; background-color: #f9f9f9; padding: 20px; box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);">
        <h3>Hasil Analisis</h3>
        <p><b>URL yang dianalisis:</b> {url}</p>
        <p><b>Hasil Deteksi:</b> {prediction_result}</p>
    </div>
    """
    st.markdown(result_html, unsafe_allow_html=True)

def home():
    show_title("🛡️ Sistem Pendeteksi Situs Phishing")
    show_description("Silahkan masukkan URL website yang ingin Anda periksa statusnya")

    col1, col2, col3 = st.columns([1, 2, 1])

    with col2:
        url = st.text_input("Masukkan URL", placeholder="Contoh: https://www.example.com", key="url", help="Masukkan URL lengkap termasuk protokol (https:// atau http://)")
        
        if st.button("🔍 Deteksi URL", use_container_width=True):
            if url:
                with st.spinner('Sedang menganalisis URL...'):
                    progress_bar = st.progress(0)
                    for i in range(100):
                        time.sleep(0.01)
                        progress_bar.progress(i + 1)
                    # Setelah proses selesai
                    prediction_result, processed_url = predict_from_url(url, model_2)
                    show_result(url, prediction_result)
                    
                    if st.button("🔄 Deteksi URL Lain", use_container_width=True, on_click=reset_form):
                        st.experimental_rerun()
            else:
                st.error("Mohon masukkan URL terlebih dahulu!")

def about():
    show_title("ℹ️ Tentang Sistem")
    st.markdown("""
        <div style='padding: 20px; border-radius: 10px; background-color: #f0f2f6; text-align: justify;'>
            <h3>Sistem Pendeteksi Situs Phishing</h3>
            <p>
                Sistem ini dirancang untuk membantu pengguna dalam mengidentifikasi potensi risiko dari sebuah website sebelum mereka mengaksesnya. Dengan menggunakan analisis URL, sistem mampu mendeteksi apakah suatu website berpotensi menjadi situs phishing atau legal. 
            </p>
            <p>
                Sistem dibangun berdasarkan konsep klasifikasi pada machine learning dan dibantu dengan algoritma <em>Extreme Gradient Boosting</em> (XGBoost). Untuk meningkatkan performa model, digunakan teknik optimasi <em>Diversity Oriented Firefly Algorithm</em> (DOFA) yang dirancang untuk menghindari algoritma terjebak pada solusi lokal dan memberikan hasil yang lebih optimal.
            </p>
            <p>
                Perlu diketahui bahwa sistem ini masih dalam tahap pengembangan. Saat ini, deteksi yang dilakukan hanya berdasarkan analisis karakteristik dari sebuah URL tanpa melakukan analisis konten secara mendalam dari halaman web yang terkait dengan URL tersebut. 
            </p>
            <p>
                Oleh karena itu, hasil deteksi dari sistem ini harus digunakan sebagai referensi awal, dan pengguna tetap dianjurkan untuk berhati-hati serta melakukan verifikasi tambahan sebelum mengakses suatu website.
            </p>
        </div>
    """, unsafe_allow_html=True)


def main():
    st.set_page_config(page_title="Deteksi Phishing URL", page_icon="🛡️", layout="wide")
    
    # Tombol Home dan About yang lebih besar
    home_button = st.sidebar.button("Home", key="home_button", use_container_width=True)
    about_button = st.sidebar.button("About", key="about_button", use_container_width=True)

    # Mengelola navigasi
    if "page" not in st.session_state:
        st.session_state.page = "Home"  # Default page

    # Tombol aktif yang sedang dipilih
    if home_button:
        st.session_state.page = "Home"
    elif about_button:
        st.session_state.page = "About"

    # Menentukan halaman aktif
    if st.session_state.page == "Home":
        home()
    elif st.session_state.page == "About":
        about()

if __name__ == "__main__":
    main()
