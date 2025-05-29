<?php // src/vuln_extra_dots_traversal.php

header('Content-Type: text/plain; charset=utf-8');

$baseDir = realpath(__DIR__ . '/../vulnerable_files/safe_dir/') . DIRECTORY_SEPARATOR;

if (isset($_GET['file'])) {
    $userFile = $_GET['file']; // Misal: ../secret_dir/secret.txt.........

    $filePath = $baseDir . $userFile;

    echo "Base Directory: " . htmlspecialchars($baseDir) . "\n";
    echo "User Input ('file'): " . htmlspecialchars($userFile) . "\n";
    echo "Attempting to access (constructed path): " . htmlspecialchars($filePath) . "\n";

    // Perilaku realpath() terhadap trailing dots bergantung pada OS.
    // Windows: Mengabaikan trailing dots.
    // Linux: Mempertahankan trailing dots sebagai bagian dari nama file.
    $realFullPath = realpath($filePath);
    echo "Resolved real path: " . ($realFullPath ? htmlspecialchars($realFullPath) : 'Path does not exist or is invalid') . "\n\n";

    if ($realFullPath && file_exists($realFullPath) && is_file($realFullPath) && is_readable($realFullPath)) {
        echo "--- File Content Start ---\n";
        echo htmlspecialchars(file_get_contents($realFullPath));
        echo "\n--- File Content End ---";
    } else {
        echo "Error: File not found, not a file, or not readable at resolved path.";
        echo "\nNote: Behavior with trailing dots is OS-dependent.";
        if (str_contains(strtolower(PHP_OS), 'win') && $realFullPath === false) {
            // Coba lagi tanpa dots jika di Windows dan realpath gagal, untuk melihat apakah itu masalahnya
            $trimmedFile = rtrim($userFile, '.');
            $trimmedPath = $baseDir . $trimmedFile;
            $realTrimmedPath = realpath($trimmedPath);
             echo "\nAttempting access with trimmed dots (Windows heuristic): " . htmlspecialchars($trimmedPath);
             echo "\nResolved real path (trimmed): " . ($realTrimmedPath ? htmlspecialchars($realTrimmedPath) : 'Path does not exist or is invalid');
        }
    }
} else {
    echo "Usage: ?file=<path_with_trailing_dots>";
}
?>