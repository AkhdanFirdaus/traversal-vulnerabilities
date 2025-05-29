<?php // src/vuln_unicode_traversal.php

header('Content-Type: text/plain; charset=utf-8');

function custom_unsafe_unicode_decoder($str) {
    return preg_replace_callback('/%u([0-9a-fA-F]{4})/', function ($match) {
        return mb_convert_encoding(pack('H*', $match[1]), 'UTF-8', 'UCS-2BE');
    }, $str);
}

$baseDir = realpath(__DIR__ . '/../vulnerable_files/safe_dir/') . DIRECTORY_SEPARATOR;

if (isset($_GET['path_unicode'])) {
    $rawUnicodePath = $_GET['path_unicode'];
    $decodedPathFromFunc = custom_unsafe_unicode_decoder($rawUnicodePath);
    $normalizedDecodedPath = str_replace(["/", "\u{2216}", "\u{FF0F}"], DIRECTORY_SEPARATOR, $decodedPathFromFunc);
    $filePath = $baseDir . $normalizedDecodedPath;

    echo "Base Directory: " . htmlspecialchars($baseDir) . "\n";
    echo "Raw Unicode Input: " . htmlspecialchars($rawUnicodePath) . "\n";
    echo "Decoded by custom_unsafe_unicode_decoder: " . htmlspecialchars($decodedPathFromFunc) . "\n";
    echo "Normalized Decoded Path (for file access): " . htmlspecialchars($normalizedDecodedPath) . "\n";
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
    echo "Usage: ?path_unicode=<uri_encoded_unicode_payload>";
}
?>