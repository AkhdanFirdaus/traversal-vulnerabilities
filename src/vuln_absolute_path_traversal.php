<?php // src/vuln_absolute_path_traversal.php

header('Content-Type: text/plain');

// Base directory untuk operasi file relatif (jika input tidak absolut)
$scriptSafeBaseDir = realpath(__DIR__ . '/../vulnerable_files/safe_dir/') . DIRECTORY_SEPARATOR;

// Root untuk sistem file yang disimulasikan (untuk path absolut dalam tes)
$simulatedFSRoot = realpath(__DIR__ . '/../vulnerable_files');


if (isset($_GET['path'])) {
    $userInputPath = $_GET['path']; // e.g., "/etc/passwd" or "C:\\Windows\\..." or "relative_file.txt"
    $isAbsoluteUnix = str_starts_with($userInputPath, '/');
    // Perbaikan untuk deteksi path absolut Windows yang lebih robust
    $isAbsoluteWindows = preg_match('/^[A-Za-z]:(\\\\|\/)/', $userInputPath) === 1;

    $finalPathToRead = null;

    if ($isAbsoluteUnix || $isAbsoluteWindows) {
        echo "Input appears to be an absolute path.\n";
        // Dalam lingkungan tes ini, kita memetakan path absolut ke dalam $simulatedFSRoot
        $effectivePath = '';
        if ($isAbsoluteUnix) {
            // Misal: /etc/passwd -> $simulatedFSRoot/etc/passwd
            $effectivePath = $simulatedFSRoot . $userInputPath;
        } else { // Windows
            // Misal: C:\Windows\file -> $simulatedFSRoot/Windows/file
            // Menghapus drive letter dan backslash awal, lalu menggabungkan
            $pathWithoutDrive = preg_replace('/^[A-Za-z]:(\\\\|\/)?/', '', $userInputPath);
            $effectivePath = $simulatedFSRoot . DIRECTORY_SEPARATOR . str_replace(['\\', '/'], DIRECTORY_SEPARATOR, $pathWithoutDrive);
        }
        $finalPathToRead = realpath($effectivePath);
        echo "Simulated absolute path processing. Effective target: " . $effectivePath . "\n";
    } else {
        // Path relatif, proses seperti biasa relatif terhadap $scriptSafeBaseDir
        echo "Input appears to be a relative path.\n";
        $effectivePath = $scriptSafeBaseDir . $userInputPath;
        $finalPathToRead = realpath($effectivePath);
        echo "Effective target: " . $effectivePath . "\n";
    }

    echo "Attempting to read: " . ($finalPathToRead ?: 'N/A (path invalid before realpath)') . "\n";
    echo "Resolved real path (final attempt): " . ($finalPathToRead ?: 'Path does not exist or is invalid') . "\n\n";

    if ($finalPathToRead && file_exists($finalPathToRead) && is_readable($finalPathToRead) && is_file($finalPathToRead)) {
        echo file_get_contents($finalPathToRead);
    } else {
        echo "Error: File not found or not readable at final path.";
    }
} else {
    echo "Usage: ?path=<absolute_or_relative_path>";
}
?>