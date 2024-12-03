# -*- coding: utf-8 -*-

#Library
import numpy as np
import pandas as pd
import requests
import string
import re
import http.client
import math
import validators
import joblib

from xgboost import XGBClassifier
from urllib.parse import urlparse, unquote
from collections import Counter
from IPython.display import clear_output

#Model Prediksi
model_path = './Final_Model/DOFA-XGBoost_model.json'
#List URL Short
list_short = pd.read_csv('./Final_Model/short_link_list.csv')
#List Top Level Domain
list_TLD = pd.read_csv('./Final_Model/tlds.csv')

#Menyimpan ke dalam variabel
# Membuat objek model
model_2 = XGBClassifier()
# Memuat model dari file JSON
model_2.load_model(model_path)

list_short = list_short['list'].to_list()
list_TLD = list_TLD['TLD'].str.lower().to_list()

"""##Membuat Fungsi Ekstraksi URL"""

# Fungsi untuk menambahkan skema jika tidak ada
def add_scheme_if_missing(url):
    if "://" not in url:
        url = "http://" + url
    return urlparse(url)

# Fungsi untuk mengekstraksi domain
def extract_domain(url):
    try:
        return add_scheme_if_missing(url).netloc
    except ValueError as e:
        return None

#Fungsi Untuk Menghitung Jumlah karakter Khusus pada url
def count_suspicious_characters(url):
    parsed_url = urlparse(url)
    # Mengabaikan protokol
    url_tanpa_protokol = url.replace(f"{parsed_url.scheme}://", "", 1)

    # Simbol yang dihitung
    symbols_to_count = '`%#^$&-*:'

    # Menghitung jumlah simbol yang sesuai
    suspicious_char_count = sum(1 for char in url_tanpa_protokol if char in symbols_to_count)

    return suspicious_char_count

#Fungsi Untuk Menghitung Rasio Jumlah karakter Khusus pada url
def ratio_special_characters(url):
    symbols = count_suspicious_characters(url)

    # Menghitung jumlah karakter alfanumerik
    alphanumeric = sum(1 for char in url if char.isalnum())

    # Menghitung rasio
    return symbols / alphanumeric if alphanumeric > 0 else 0

#Fungsi untuk menghitung jumlah garis miring '/' pada url
def count_slashes(url):
    parsed_url = urlparse(url)
    # Mengabaikan protokol
    url_tanpa_protokol = url.replace(f"{parsed_url.scheme}://", "", 1)

    # Menghitung jumlah garis miring setelah protokol dihapus
    return url_tanpa_protokol.count('/')

# Daftar kata-kata mencurigakan
suspicious_keywords = [
    'access', 'accounts', 'auth', 'security', 'portal', 'user', 'company', 'admin', 'credential', 'identity',
    'login', 'password', 'privilege', 'token', 'validation', 'assurance', 'availability', 'confidentiality',
    'integrity', 'privacy', 'safety', 'trust', 'verification', 'check', 'key', 'lock', 'biometrics',
    'authorize', 'authentication', 'session', 'profile', 'service', 'support', 'notify',
    'email', 'account', 'update', 'secure', 'notification', 'transaction', 'validate', 'confirmation',
    'manager', 'assistant', 'dashboard', 'information', 'communication', 'finance', 'maintenance',
    'customer', 'invoice', 'billing', 'subscription', 'order', 'shipment',
    'purchase', 'alert', 'receipt', 'accountinfo', 'payment', 'invoiceinfo', 'orderinfo'
]
suspicious_keywords_set = set(suspicious_keywords)

# Fungsi untuk menghitung jumlah kata mencurigakan dalam sebuah URL
def count_suspicious_keywords(url):
    parsed_url = urlparse(url)
    # Menghilangkan protokol
    url_tanpa_protokol = url.replace(f"{parsed_url.scheme}://", "", 1).lower()

    # Menghapus simbol yang tidak diinginkan, kecuali titik, garis miring, dan tanda hubung
    cleaned_url = re.sub(r'[^\w./\-]', '', url_tanpa_protokol)

    # Memisahkan URL berdasarkan pemisah titik (.), garis miring (/), dan tanda hubung (-)
    words = re.split(r'[./\-]', cleaned_url)

    # Menghapus elemen kosong
    words = [word for word in words if word]

    # Mencari kata mencurigakan menggunakan substring matching
    suspicious_words = []
    for word in words:
        for keyword in suspicious_keywords_set:
            if keyword in word:
                suspicious_words.append(keyword)
                break  # Hindari duplikasi kata mencurigakan dari kata yang sama
    return len(suspicious_words)
# Terapkan fungsi pada dataset

#Fungsi untuk menghitung jumlah titik '.' pada url
def count_dots(url):
    # Menghitung jumlah '.' dalam URL
    return url.count('.')

#Fungsi untuk menghitung jumlah tanda hubung '-' pada url
def count_dashes(url):
    # Menghitung jumlah '-' dalam URL
    return url.count('-')

# Fungsi untuk mendeteksi apakah protokol adalah 'http' atau 'https', atau 'Lainnya', atau 'None'
# Ganti nama memiliki protokol
def has_protocol(url):
    # Pola regex untuk mencocokkan protokol apapun
    protocol_pattern = r'^(\w+)://'
    match = re.match(protocol_pattern, url)

    if match:
        protocol = match.group(1)
        if protocol in ['http', 'https']:
            return protocol  # Mengembalikan 'http' atau 'https'
        else:
            return 'other'  # Mengembalikan 'other' untuk protokol selain http/https
    else:
        return 'none'  # Mengembalikan 'none' jika tidak ada protokol

# Fungsi untuk menghitung entropi domain
def entropy(string):
    p, lns = Counter(string), float(len(string))
    return -sum(count/lns * math.log2(count/lns) for count in p.values())

# Fungsi untuk menghitung rasio panjang
def ratio(part, whole):
    return len(part) / len(whole) if whole else 0

# Fungsi untuk menghitung rasio angka dalam sebuah string
def digit_ratio(string):
    digits = sum(c.isdigit() for c in string)
    return digits / len(string) if len(string) > 0 else 0

# Fungsi untuk menghitung panjang rata-rata token dalam path
def avg_token_length(path):
    tokens = path.split('/')
    if len(tokens) > 1:
        return sum(len(token) for token in tokens) / len(tokens)
    return 0

# Fungsi untuk menghitung rasio panjang karakter yang berkelanjutan
def continuous_char_ratio(string):
    max_seq = 1
    current_seq = 1
    for i in range(1, len(string)):
        if string[i] == string[i-1]:
            current_seq += 1
            max_seq = max(max_seq, current_seq)
        else:
            current_seq = 1
    return max_seq / len(string) if len(string) > 0 else 0

# Fungsi untuk menghitung jumlah token dalam domain
def domain_token_count(domain):
    return len(domain.split('.'))

# Fungsi untuk mengekstrak TLD dari domain
def extract_tld(domain):
    tokens = domain.split('.')
    tld = tokens[-1] if len(tokens) > 1 else ''
    cleaned_tld = re.sub(r'[^a-z]', '', tld.lower())
    return 1 if cleaned_tld in list_TLD else 0

# Fungsi untuk menghitung panjang domain
def domain_length(domain):
    return len(domain)

# Fungsi untuk menghitung panjang nama file di URL
def file_name_length(path):
    filename = path.split('/')[-1]
    return len(filename) if filename else 0

# Fungsi untuk menghitung jumlah digit dalam query
def query_digit_count(query):
    return sum(c.isdigit() for c in query)

# Fungsi untuk menghitung panjang token terpanjang dalam path
def longest_path_token_length(path):
    tokens = path.split('/')
    return max(len(token) for token in tokens) if tokens else 0

# Fungsi untuk menambahkan protokol
def parse_with_default_scheme(url):
    if "://" not in url:
        url = "http://" + url
    return urlparse(url)

#Fungsi untuk melakukan label encoding
def Label_Encoding(value):
    if value is True:
        return 1
    elif value is False or value == 'none':
        return 0
    elif value == 'https':
        return 1
    elif value == 'http':
        return 2
    else:
        return 3

#Fungsi untuk menghapus spasi pada URL
def remove_whitespace(url):
    # Hapus spasi di awal dan di akhir, lalu hapus semua spasi di tengah
    return url.strip().replace(" ", "")

"""##Membuat Fungsi Validasi URL"""

#Fungsi untuk melakukan validasi URL
def validate_url(url):
    # Periksa apakah URL memiliki format yang valid secara sintaksis
    if not validators.url(url):
        return False  # Tidak valid secara sintaksis

    # Tambahkan skema jika tidak ada
    if "://" not in url:
        url = "http://" + url

    try:
        response = requests.get(url, allow_redirects=True, timeout=3)
        # Bisa menambahkan pengecekan lebih lanjut berdasarkan content-type, dsb.
        if response.status_code in [200, 301, 302]:
            return True
        else:
            return False
    except requests.exceptions.RequestException:
        return False

#Fungsi untuk melakukan unshorten URL
def unshorten_url(url):
    try:
        # Menambahkan skema jika tidak ada protokol
        if "://" not in url:
            url = "http://" + url

        # Melakukan permintaan GET ke URL dengan mengizinkan pengalihan (redirects)
        response = requests.get(url, allow_redirects=True, timeout=5)

        return response.url
    except requests.exceptions.RequestException:
        return None

#Fungsi untuk menambahkan protokol jika URL yang diinputkan tidak memiliki protokol
def get_protocol(url):
    if "://" not in url:
        url = 'http://' + url

    try:
        response = requests.get(url, allow_redirects=True, timeout=3)

        # Jika URL dialihkan, kembalikan URL yang sudah di-redirect
        if response.history:
            return response.url

        return url
    except requests.exceptions.RequestException:
        return url  # Kembalikan URL asli jika ada kesalahan

"""##Membuat Fungsi untuk Memproses URL"""

#Fungsi untuk Mengekstrak Fitur pada URL yang diinputkan Pengguna
def extract_features(url):
    url = remove_whitespace(url)
    # Validasi URL terlebih dahulu
    if not validate_url(url):
        return None, {'error': 'URL Yang Anda Inputkan TIDAK VALID, Silahkan Inputkan URL Dengan Format yang Valid'}

    protokol = has_protocol(url)
    domain = extract_domain(url)

    if domain in list_short:
        url = unshorten_url(url)
        if url is None:  # Jika unshorten_url gagal
            return None, {'error': 'Proses UNSHORTEN GAGAL, Periksa Kembali URL Anda'}
    elif protokol == 'none':
        url = get_protocol(url)
    else:
        url = url

    processed_url = url  # Simpan URL yang sudah diproses

    features = {
        'panjang_url': len(url),
        'panjang_domain': domain_length(parse_with_default_scheme(url).netloc),
        'panjang_nama_file': file_name_length(parse_with_default_scheme(url).path),
        'panjang_token_path_terpanjang': longest_path_token_length(parse_with_default_scheme(url).path),
        'jumlah_angka_kueri': query_digit_count(parse_with_default_scheme(url).query),
        'jumlah_token_domain': domain_token_count(parse_with_default_scheme(url).netloc),
        'jumlah_garis_miring': count_slashes(url),
        'jumlah_kata_mencurigakan': count_suspicious_keywords(url),
        'jumlah_titik': count_dots(url),
        'jumlah_tanda_hubung': count_dashes(url),
        'jumlah_karakter_mencurigakan': count_suspicious_characters(url),
        'suspicious_char_ratio': ratio_special_characters(url),
        'arg_path_ratio': ratio(parse_with_default_scheme(url).query, parse_with_default_scheme(url).path),
        'arg_url_ratio': ratio(parse_with_default_scheme(url).query, url),
        'arg_domain_ratio': ratio(parse_with_default_scheme(url).query, parse_with_default_scheme(url).netloc),
        'domain_url_ratio': ratio(parse_with_default_scheme(url).netloc, url),
        'path_url_ratio': ratio(parse_with_default_scheme(url).path, url),
        'path_domain_ratio': ratio(parse_with_default_scheme(url).path, parse_with_default_scheme(url).netloc),
        'digit_ratio_url': digit_ratio(url),
        'digit_ratio_filename': digit_ratio(parse_with_default_scheme(url).path.split('/')[-1]),
        'digit_ratio_after_path': digit_ratio(parse_with_default_scheme(url).query),
        'continuous_char_ratio': continuous_char_ratio(parse_with_default_scheme(url).netloc),
        'avg_token_length': avg_token_length(parse_with_default_scheme(url).path),
        'memiliki_protokol': Label_Encoding(has_protocol(url)),
        'tld': extract_tld(parse_with_default_scheme(url).netloc),
        'domain_entropy': entropy(parse_with_default_scheme(url).netloc)
    }

    return processed_url, features

# Fungsi untuk membuat prediksi dari URL yang diinputkan pengguna
def predict_from_url(url, model):
    original_url = url  # Menyimpan URL asli

    # Proses untuk memvalidasi dan mengubah URL jika perlu
    processed_url, new_features = extract_features(url)
    if 'error' in new_features:
        return new_features['error'], original_url  # Mengembalikan error dan URL asli

    # Mendapatkan URL yang sudah diproses (misalnya setelah unshorten atau penambahan protokol)
    #processed_url = new_features.get('protokol', url)  # Ambil URL yang sudah diproses dari fitur

    # Buat prediksi
    new_features_df = pd.DataFrame([new_features])
    prediction = model.predict(new_features_df)

    # Mengubah hasil prediksi menjadi deskripsi yang lebih informatif
    if prediction[0] == 1:
        prediction_result = f"'{processed_url}'\n adalah URL LEGAL."
    else:
        prediction_result = f"'{processed_url}'\n adalah URL PHISHING."

    # Mengembalikan hasil prediksi dan URL yang telah diproses
    return prediction_result, processed_url

# Looping utama
def main():
    while True:
        clear_output(wait=True)
        # Meminta pengguna untuk memasukkan URL baru
        url_baru = input("\nMasukkan URL yang ingin dideteksi: ")

        # Melakukan prediksi menggunakan URL baru dan model
        prediksi_baru, processed_url = predict_from_url(url_baru, model_2)

        # Menampilkan hasil prediksi
        print(f"\n{prediksi_baru}")

        while True:
            user_choice = input("\nApakah Anda ingin memasukkan URL lain? (y/n): ").lower()
            if user_choice == 'y':
                break
            elif user_choice == 'n':
                print("Program dihentikan.")
                return
            else:
                print("Input yang Anda masukkan salah, harap menginputkan 'y' untuk memasukkan kembali URL atau 'n' untuk menghentikan program")

if __name__ == "__main__":
    main()

