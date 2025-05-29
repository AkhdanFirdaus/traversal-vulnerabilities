<?php // src/vuln_double_encoded_traversal.php

header('Content-Type: text/plain; charset=utf-8');

$baseDir = realpath(__DIR__ . '/../vulnerable_files/safe_dir/') . DIRECTORY_SEPARATOR;

if (isset($_GET['file'])) {
    $singlyDecodedFileByPHP = $_GET['file'];
    $doublyDecodedFile = urldecode($singlyDecodedFileByPHP);
    $filePath = $baseDir . $doublyDecodedFile;

    echo "Base Directory: " . htmlspecialchars($baseDir) . "\n";
    echo "Input \$_GET['file'] (expected to be singly decoded by PHP): " . htmlspecialchars($singlyDecodedFileByPHP) . "\n";
    echo "After script's urldecode() (expected to be doubly decoded): " . htmlspecialchars($doublyDecodedFile) . "\n";
    echo "Attempting to access (constructed path): " . htmlspecialchars($filePath) . "\n";

    $realFullPath = realpath($filePath);
    echo "Resolved real path: " . ($realFullPath ? htmlspecialchars($realFullPath) : 'Path does not exist or is invalid') . "\n\n";

    if ($realFullPath && file_exists($realFullPath) && is_file($realFullPath) && is_readable($realFullPath)) {
        echo "--- File Content Start ---\n";
        echo htmlspecialchars(file_get_contents($realFullPath));
        echo "\n--- File Content End ---";
    } else {
        echo "Error: File not found, not a file, or not readable at resolved path.";
    }
} else {
    echo "Usage: ?file=<double_url_encoded_payload_where_php_does_first_decode>";
}
?>
