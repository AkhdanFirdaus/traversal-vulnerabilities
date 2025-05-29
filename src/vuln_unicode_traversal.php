<?php
// Vulnerable to: %u002e%u002e%u002f (../), %u2216 (/) if custom decoded
// Example URL: vuln_unicode_traversal.php?path_unicode=%u002e%u002e%u2216secret_files%u2216secret.txt
// (This URL itself won't be auto-decoded by PHP for %u, script must do it)

header('Content-Type: text/plain');

// Custom vulnerable function to decode %uXXXX sequences
function custom_unicode_decoder($str) {
    return preg_replace_callback('/%u([0-9a-fA-F]{4})/', function ($match) {
        return mb_convert_encoding(pack('H*', $match[1]), 'UTF-8', 'UCS-2BE');
    }, $str);
}

$baseDir = 'public_files/';

if (isset($_GET['path_unicode'])) {
    $rawUnicodePath = $_GET['path_unicode']; // e.g., "%u002e%u002e%u2216secret_files%u2216secret.txt"

    // Vulnerability: Application uses a custom/unsafe decoder
    $decodedPath = custom_unicode_decoder($rawUnicodePath); // e.g., "../secret_files/secret.txt"

    $filePath = $baseDir . $decodedPath;

    echo "Raw Unicode input: " . $rawUnicodePath . "\n";
    echo "Decoded path (after custom_unicode_decoder): " . $decodedPath . "\n";
    echo "Attempting to read: " . $filePath . "\n";
    echo "Resolved real path: " . realpath($filePath) . "\n\n";

    if (file_exists($filePath) && is_readable($filePath)) {
        echo file_get_contents($filePath);
    } else {
        echo "Error: File not found or not readable.";
    }
} else {
    echo "Usage: ?path_unicode=<percent_u_encoded_path>";
}
?>