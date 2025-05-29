<?php
// Vulnerable to: ../secret_files/secret.txt... (trailing dots)
// Example URL: vuln_extra_dots_traversal.php?file=../secret_files/secret.txt.........
// Some OS (like Windows) might truncate trailing dots from filenames.

header('Content-Type: text/plain');
$baseDir = 'public_files/';

if (isset($_GET['file'])) {
    $userFile = $_GET['file']; // e.g., "../secret_files/secret.txt..."
    $filePath = $baseDir . $userFile;

    echo "Attempting to read: " . $filePath . "\n";
    // On Windows, file_exists("file.txt...") might be true if "file.txt" exists.
    // realpath() would also show the normalized path.
    echo "Resolved real path: " . realpath($filePath) . "\n\n";

    if (file_exists($filePath) && is_readable($filePath)) {
        echo file_get_contents($filePath);
    } else {
        echo "Error: File not found or not readable.";
        echo "\nNote: This vulnerability is highly OS-dependent regarding how trailing dots are handled.";
    }
} else {
    echo "Usage: ?file=<path_with_trailing_dots>";
}
?>