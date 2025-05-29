<?php
// Vulnerable to: .../...//, ...\\...\\\\, ..\\/..\\/target
// Example URL: vuln_obfuscated_mixed_slashes_traversal.php?file=..././.../....//../secret_files/secret.txt
// Example URL: vuln_obfuscated_mixed_slashes_traversal.php?file=..\\/..\\/secret_files\\secret.txt

header('Content-Type: text/plain');
$baseDir = 'public_files/';

if (isset($_GET['file'])) {
    $userFile = $_GET['file'];
    $filePath = $baseDir . $userFile; // e.g. public_files/.../...//../secret_files/secret.txt

    echo "Attempting to read: " . $filePath . "\n";
    // PHP's path resolution (via realpath or file functions) might normalize these.
    echo "Resolved real path: " . realpath($filePath) . "\n\n";

    if (file_exists($filePath) && is_readable($filePath)) {
        echo file_get_contents($filePath);
    } else {
        echo "Error: File not found or not readable.";
    }
} else {
    echo "Usage: ?file=<obfuscated_path>";
}
?>