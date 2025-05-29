# Proyek Dummy Uji Path Traversal PHP

Proyek ini adalah sebuah aplikasi PHP sederhana yang sengaja dibuat rentan terhadap serangan _Path Traversal_ (juga dikenal sebagai _Directory Traversal_). Tujuannya adalah untuk demonstrasi, pembelajaran, dan pengujian _tools_ keamanan atau _mutation testing_ seperti Infection.

## Struktur Proyek (Skeleton)

Berikut adalah penjelasan mengenai struktur direktori dan file utama dalam proyek ini:
`
path-traversal-test/
├── src/
│   └── vuln_file_read.php        # Script PHP yang rentan, target utama pengujian
├── tests/
│   ├── BaseVulnerableScriptTest.php # Kelas dasar abstrak untuk semua file tes
│   ├── BasicFunctionalityTest.php   # Tes untuk fungsionalitas dasar (akses file legit)
│   ├── Cwe22PathTraversalTest.php   # Tes spesifik untuk CWE-22
│   ├── Cwe23PathTraversalTest.php   # Tes spesifik untuk CWE-23
│   ├── ... (file tes lain per CWE) ...
│   └── Cwe36PathTraversalTest.php   # Tes spesifik untuk CWE-36
├── vulnerable_files/             # Direktori berisi file "sensitif" dan "aman"
│   ├── safe_dir/                 # Direktori yang seharusnya aman diakses
│   │   ├── legit.txt
│   │   └── modules/public_module.php
│   ├── secret_dir/               # Direktori berisi file rahasia
│   │   ├── secret.txt
│   │   ├── admin/panel.php
│   │   └── config/db.php
│   ├── etc/                      # Simulasi direktori sistem
│   │   └── passwd
│   └── Windows/                  # Simulasi direktori sistem Windows
│       └── System32/drivers/etc/hosts
├── patterns.json                 # File JSON berisi daftar pola serangan Path Traversal (disediakan pengguna)
├── composer.json                 # File konfigurasi Composer untuk dependensi (PHPUnit, Infection)
├── phpunit.xml.dist              # File konfigurasi PHPUnit
└── infection.json.dist           # File konfigurasi Infection (mutation testing)
`


**Penjelasan Detail:**

* **`src/vuln_file_read.php`**:
    * Ini adalah skrip inti yang memiliki kerentanan Path Traversal.
    * Skrip ini menerima parameter `file` melalui `$_GET` (misalnya, `vuln_file_read.php?file=some_file.txt`).
    * Tujuannya adalah untuk membaca dan menampilkan konten file yang diminta.
    * Kerentanannya terletak pada bagaimana skrip ini menggabungkan input pengguna dengan _base directory_ (`$sandboxBase`) tanpa sanitasi yang memadai, memungkinkan pengguna untuk "naik" direktori menggunakan pola seperti `../` atau `..\`.
    * `$sandboxBase` dihitung relatif terhadap lokasi skrip itu sendiri (`__DIR__`), mengarah ke `../vulnerable_files/safe_dir/`.

* **`tests/`**:
    * Direktori ini berisi semua _test case_ PHPUnit.
    * **`BaseVulnerableScriptTest.php`**: Kelas abstrak yang menyediakan fungsionalitas dasar untuk semua kelas tes, seperti metode untuk mengeksekusi skrip rentan (`executeVulnerableScript`), mengambil konten file target untuk asserstion (`getTargetFileContent`), dan metode `runFileReadTest` yang generik. `projectRoot` di sini dihitung dari lokasi file tes (`__DIR__ . '/..'`), yang akan menunjuk ke root proyek. Akses ke `vulnerable_files` untuk assertion menggunakan `$this->projectRoot . '/vulnerable_files/...'`.
    * **`BasicFunctionalityTest.php`**: Menguji skenario akses file yang sah ke `safe_dir/legit.txt` untuk memastikan skrip berfungsi dalam kondisi normal.
    * **`CweXXPathTraversalTest.php`**: Setiap file ini didedikasikan untuk menguji pola serangan yang terkait dengan Common Weakness Enumeration (CWE) tertentu (misalnya, CWE-22 untuk _Basic Path Traversal_, CWE-25 untuk _Absolute Path_, dll.). Setiap kelas berisi:
        * Metode tes (misalnya, `testPathTraversal`) yang menggunakan `@dataProvider`.
        * Metode _data provider_ (misalnya, `cweXXPatternsProvider`) yang menyediakan berbagai _payload_ serangan dan target file yang diharapkan.
        * Metode tes ini memanggil `runFileReadTest` dari kelas dasar untuk melakukan eksekusi dan assertion.

* **`vulnerable_files/`**:
    * Berisi file dan direktori yang akan menjadi target serangan Path Traversal.
    * **`safe_dir/`**: Direktori yang seharusnya menjadi satu-satunya tempat skrip `vuln_file_read.php` boleh membaca file secara default.
    * **`secret_dir/`**: Berisi file-file "rahasia" yang seharusnya tidak dapat diakses oleh pengguna melalui skrip.
    * **`etc/passwd`** dan **`Windows/.../hosts`**: Simulasi file sistem sensitif yang sering menjadi target serangan Path Traversal.
    * Struktur ini memungkinkan pengujian berbagai skenario traversal, baik ke direktori saudara, direktori induk, maupun ke path absolut (simulasi).

* **`patterns.json`**:
    * File ini (disediakan oleh pengguna) mendefinisikan berbagai pola serangan Path Traversal, dikategorikan berdasarkan CWE.
    * Tes PHPUnit menggunakan pola-pola ini dalam _data provider_ mereka untuk mencoba mengeksploitasi kerentanan.

* **`composer.json`**:
    * Mengelola dependensi proyek, terutama PHPUnit untuk _unit testing_ dan Infection untuk _mutation testing_.
    * Mendefinisikan skrip untuk menjalankan tes (`composer test`) dan Infection (`composer infection`).
    * Mengatur autoloading PSR-4 untuk _namespaces_ (misalnya, `MyProject\PathTraversal\Tests` untuk direktori `tests/`).

* **`phpunit.xml.dist`**:
    * File konfigurasi standar untuk PHPUnit.
    * Menentukan _bootstrap file_ (`vendor/autoload.php`), direktori tes, dan pengaturan _code coverage_.

* **`infection.json.dist`**:
    * File konfigurasi untuk Infection.
    * Menentukan direktori source code yang akan dimutasi (`src/`), _timeout_, _minimum MSI (Mutation Score Indicator)_, dan pengaturan _logging_.

## Cara Kerja Dummy Project

1.  **Kerentanan Inti (`vuln_file_read.php`)**:
    * Skrip mengambil nama file dari input `$_GET['file']`.
    * Jika input adalah path relatif, skrip menggabungkannya dengan `$sandboxBase` (yang defaultnya adalah `PROJECT_ROOT/vulnerable_files/safe_dir/`).
    * Jika input terdeteksi sebagai path absolut, skrip akan mencoba menggunakan path tersebut secara langsung (ini juga merupakan vektor kerentanan).
    * Tidak ada validasi atau sanitasi yang kuat untuk mencegah penggunaan `../` atau `..\` untuk keluar dari `$sandboxBase` atau untuk membatasi akses pada path absolut.
    * Fungsi `realpath()` digunakan, yang akan mengkanonikalisasi path (misalnya, mengubah `dir/../file` menjadi `file`), namun kerentanannya adalah **tidak adanya pengecekan** apakah path yang sudah dikanonikalisasi tersebut masih berada dalam direktori yang diizinkan.

2.  **Pengujian dengan PHPUnit (`tests/`)**:
    * Setiap kelas `CweXXPathTraversalTest.php` fokus pada satu jenis kerentanan Path Traversal.
    * _Data provider_ dalam setiap kelas menyediakan berbagai _payload_ serangan (misalnya, `../../secret_dir/secret.txt`, `/app/vulnerable_files/etc/passwd`).
    * Metode `executeVulnerableScript` di `BaseVulnerableScriptTest.php` mensimulasikan permintaan ke `vuln_file_read.php` dengan mengatur `$_GET` dan menangkap outputnya menggunakan _output buffering_ (`ob_start`, `ob_get_clean`).
    * Metode `runFileReadTest` kemudian membandingkan output dari skrip dengan konten file target yang diharapkan (misalnya, konten dari `vulnerable_files/secret_dir/secret.txt`).
    * **Tes dianggap "lulus" jika serangan berhasil**, yaitu jika konten file rahasia berhasil dibaca. Ini menunjukkan bahwa kerentanan memang ada.

3.  **Mutation Testing dengan Infection**:
    * Setelah menjalankan `composer infection`, Infection akan membuat sedikit perubahan (mutasi) pada kode di `src/vuln_file_read.php`. Contoh mutasi: mengubah `.` menjadi `_`, menghapus sebuah kondisi, mengganti `realpath` dengan `basename`, dll.
    * Untuk setiap mutan, Infection akan menjalankan kembali _test suite_ PHPUnit.
    * **Mutan "Killed"**: Jika sebuah mutasi (misalnya, penambahan `basename($_GET['file'])` yang efektif memperbaiki kerentanan) menyebabkan tes PHPUnit (yang tadinya "lulus" karena berhasil mengeksploitasi) menjadi "gagal" (karena eksploitasi tidak lagi berhasil), maka mutan tersebut dianggap "terbunuh". Ini adalah hasil yang baik, menunjukkan tes efektif mendeteksi perbaikan.
    * **Mutan "Survived"**: Jika tes PHPUnit tetap "lulus" (eksploitasi masih berhasil) meskipun kode sudah dimutasi, atau jika tes "gagal" karena alasan lain yang tidak terkait dengan perbaikan kerentanan, maka mutan tersebut "selamat". Ini bisa mengindikasikan bahwa:
        * Mutasi tersebut tidak relevan atau tidak memperbaiki kerentanan.
        * Cakupan tes kurang, atau tes tidak cukup spesifik untuk menangkap efek mutasi tersebut.
    * Tujuannya adalah untuk mencapai _Mutation Score Indicator_ (MSI) yang tinggi, yang berarti sebagian besar mutan berhasil "dibunuh" oleh _test suite_.

## Tujuan Penggunaan

* **Pembelajaran**: Memahami bagaimana serangan Path Traversal bekerja dan bagaimana kerentanan ini bisa muncul dalam kode PHP.
* **Demonstrasi**: Menunjukkan secara praktis dampak dari kerentanan ini.
* **Pengujian Tools**: Dapat digunakan untuk menguji efektivitas _static analysis security testing_ (SAST) _tools_ atau _dynamic analysis security testing_ (DAST) _tools_ dalam mendeteksi kerentanan Path Traversal.
* **Pengembangan Tes**: Sebagai latihan dalam menulis _test case_ yang efektif untuk kerentanan keamanan, terutama dalam konteks _mutation testing_ untuk memastikan _test suite_ kuat.

Proyek ini dirancang agar mudah dipahami dan dimodifikasi untuk berbagai skenario pengujian Path Traversal.
