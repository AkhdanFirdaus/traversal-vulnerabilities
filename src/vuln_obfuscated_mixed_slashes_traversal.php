<?php // src/vuln_obfuscated_mixed_slashes_traversal.php
header('Content-Type: text/plain; charset=utf-8');

$baseDir = realpath(__DIR__ . '/../vulnerable_files/safe_dir/') . DIRECTORY_SEPARATOR;

if (isset($_GET['file'])) {
    $userFile = $_GET['file'];
    $filePath = $baseDir . $userFile;

    echo "Base Directory: " . htmlspecialchars($baseDir) . "\n";
    echo "User Input ('file'): " . htmlspecialchars($userFile) . "\n";
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
    echo "Usage: ?file=<obfuscated_or_mixed_slash_path>";
}
?>