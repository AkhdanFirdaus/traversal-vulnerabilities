<?php // src/vuln_basic_relative_traversal.php

header('Content-Type: text/plain; charset=utf-8');

// Basis direktori aman, tempat file seharusnya diakses.
// __DIR__ adalah /path/to/project/src
$baseDir = realpath(__DIR__ . '/../vulnerable_files/safe_dir/') . DIRECTORY_SEPARATOR;

if (isset($_GET['file'])) {
    $userFile = $_GET['file']; // Input dari pengguna

    // Kerentanan: Input pengguna langsung digabungkan ke baseDir.
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
    echo "Usage: ?file=<filename_payload>";
}
?>