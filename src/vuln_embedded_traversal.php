<?php
// Vulnerable to: images/../secret.txt, static/../config.ini, images/../../secret_files/secret.txt
// Example URL: vuln_embedded_traversal.php?resource=images/../../secret_files/secret.txt
// Example URL: vuln_embedded_traversal.php?resource=legitimate.txt/../secret_files/secret.txt

header('Content-Type: text/plain');
// Assumes resources are within 'public_files/' and an extension is often appended by the app
$baseDir = 'public_files/';

if (isset($_GET['resource'])) {
    $userResource = $_GET['resource']; // e.g., "images/../../secret_files/secret.txt"
    $filePath = $baseDir . $userResource;

    echo "Attempting to read: " . $filePath . "\n";
    echo "Resolved real path: " . realpath($filePath) . "\n\n";

    if (file_exists($filePath) && is_readable($filePath)) {
        echo file_get_contents($filePath);
    } else {
        echo "Error: File not found or not readable.";
    }
} else {
    echo "Usage: ?resource=<path_with_embedded_traversal>";
}
?>