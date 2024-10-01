# Phishing-Detection
Tugas Akhir_Mohammad Al Muktabar_120140222

Implementasi Algoritma Extreme Gradient Boosting Dalam Mendeteksi Situs Phishing Menggunakan Optimasi Diversity Oriented Firefly Algorithm

## Deskripsi :
Berisi dokumentasi program yang penulis gunakan dalam membangun model deteksi situs phishing yang terdiri dari penggunaan fungsi dataset, unshorten, feature extraction, hyperparameter tuning, final model. Penelitian ini bertujuan untuk membangun sistem deteksi situs phishing berdasarkan inputan pengguna menggunakan algoritma Extreme Gradient Boosting (XGBoost) yang dioptimalkan dengan Diversity Oriented Firefly Algorithm (DOFA) dalam menyesuaikan hyperparameter dan mengevaluasi performa DOFA dalam mengoptimalkan hyperparameter XGBoost.

### Dataset 
Folder dataset terdiri dari 3 dataset, Dataset Full merupakan dataset utama pada penelitian ini yang belum dilakukan preprocessing, dataset pengujian merupakan dataset yang digunakan untuk menguji hasil final model, dan dataset processing merupakan dataset final yang digunakan untuk melatih final model.

### Unshorten 
Folder unshorten berisi fungsi untuk melakukan unshorten pada URL yang terindikasi short link.

### Feature Extraction 
Folder feature extraction berisi potongan kode fitur - fitur yang diekstrak pada penelitian ini. Terdapat 26 fitur lexical yang di gunakan dalam penelitian ini sebagai berikut :
1. Panjang_url
2. Panjang_domain
3. Panjang_nama_file
4. Panjang_token_path _terpanjang
5. Jumlah_angka_kueri
6. Jumlah_token_domain
7. Jumlah_garis_miring
8. Jumlah_kata_mencurigakan
9. Jumlah_titik
10. Jumlah_tanda_hubung
11. 1Jumlah_karakter_mencurigakan
12. Suspicious_char_ratio
13. Arg_path_ratio
14. Arg_url_ratio
15. Arg_domain_ratio
16. Domain_url_ratio
17. Path_url_ratio
18. Path_domain_ratio
19. Digit_ratio_url
20. Digit_ratio_filename
21. Digit_ratio_after_path
22. Contonuous_char_ratio
23. Avg_token_length
24. Memiliki_protokol
25. Tld
26. Domain_entropy

### Hyperparameter Tuning
Folder hyperparameter tuning berisi potongan kode dalam melakukan optimasi hyperparameter menggunakan DOFA.

### Final Model
Folder final model berisi hasil program deteksi situs phishing yang disertai dengan file - file pendukung dalam membangun dataset.

## Referensi :
Berikut merupakan referensi - referensi yang penulis gunakan dalam membangun final model :
1. https://www.kaggle.com/datasets/harisudhan411/phishing-and-legitimate-urls (dataset utama)
2. https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset (Dataset Pengujian)
3. https://www.icann.org/resources/pages/tlds-2012-02-25-en (List TLD)
4. https://github.com/PeterDaveHello/url-shorteners/blob/master/list (List URL Short)
5. https://github.com/simplerhacking/Phishing-Keyword-List (List Kata Mencurigakan)
