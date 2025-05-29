<?php
// Vulnerable to: %252e%252e%252f (double URL encoded ../)
// Example URL: vuln_double_encoded_traversal.php?file=%252e%252e%252fsecret_files%252fsecret.txt
// $_GET automatically decodes once: %252e%252e%252f -> %2e%2e%2f
// The script then decodes it again: %2e%2e%2f -> ../

header('Content-Type: text/plain');
$baseDir = 'public_files/';

if (isset($_GET['file'])) {
    // $_GET['file'] will be singly-decoded by PHP: e.g., "%2e%2e%2fsecret_files%2fsecret.txt"
    $singlyDecodedFile = $_GET['file'];

    // Vulnerability: Application performs another urldecode
    $doublyDecodedFile = urldecode($singlyDecodedFile); // e.g., "../secret_files/secret.txt"

    $filePath = $baseDir . $doublyDecodedFile;

    echo "Singly decoded input (from \$_GET): " . $singlyDecodedFile . "\n";
    echo "Doubly decoded input (after script urldecode): " . $doublyDecodedFile . "\n";
    echo "Attempting to read: " . $filePath . "\n";
    echo "Resolved real path: " . realpath($filePath) . "\n\n";

    if (file_exists($filePath) && is_readable($filePath)) {
        echo file_get_contents($filePath);
    } else {
        echo "Error: File not found or not readable.";
    }
} else {
    echo "Usage: ?file=<double_encoded_path>";
}
?>