<?php // src/vuln_basic_relative_traversal.php

// Pola serangan yang diharapkan: ../secret_dir/secret.txt (relatif terhadap $baseDir)
// Contoh URL (jika skrip diakses langsung via web server di /src/script.php):
// ?file=../secret_dir/secret.txt

header('Content-Type: text/plain');

// __DIR__ akan menjadi /path/to/project/src
// Jadi, __DIR__ . '/../vulnerable_files/safe_dir/' akan menunjuk ke
// /path/to/project/vulnerable_files/safe_dir/
$baseDir = realpath(__DIR__ . '/../vulnerable_files/safe_dir/') . DIRECTORY_SEPARATOR;

if (isset($_GET['file'])) {
    $userFile = $_GET['file'];
    // Gabungkan baseDir dengan input pengguna
    $filePath = $baseDir . $userFile;
    // Contoh: /path/to/project/vulnerable_files/safe_dir/../secret_dir/secret.txt

    echo "Attempting to include: " . $filePath . "\n";
    // Normalisasi path untuk keamanan (yang seharusnya dilakukan kode aman)
    // realpath() akan menyelesaikan '..' dan '.' dan mengembalikan path absolut kanonis, atau false jika path tidak valid.
    $realFullPath = realpath($filePath);
    echo "Resolved real path: " . ($realFullPath ?: 'Path does not exist or is invalid') . "\n\n";

    // Kerentanan: include langsung tanpa validasi yang cukup terhadap $realFullPath
    // terhadap $baseDir setelah normalisasi.
    if ($realFullPath && file_exists($realFullPath) && is_file($realFullPath)) {
        include $realFullPath; // Rentan jika $realFullPath keluar dari $baseDir
    } else {
        echo "Error: File not found or not readable at resolved path '{$realFullPath}'. Attempted: '{$filePath}'";
    }
} else {
    echo "Usage: ?file=<filename>";
}
?>