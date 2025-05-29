<?php // src/vuln_null_byte_traversal.php

header('Content-Type: text/plain; charset=utf-8');

$baseDir = realpath(__DIR__ . '/../vulnerable_files/safe_dir/') . DIRECTORY_SEPARATOR;

if (isset($_GET['file'])) {
    $userFile = $_GET['file']; // Sudah di-URL-decode oleh PHP (%00 -> \0)
    $filePathAttempt = $baseDir . $userFile;

    echo "Base Directory: " . htmlspecialchars($baseDir) . "\n";
    echo "User Input ('file') (hex): " . bin2hex($userFile) . "\n";
    echo "Attempting to access (raw constructed path): " . htmlspecialchars($filePathAttempt) . "\n";

    $realFullPath = null;
    $message = "";
    if (strpos($filePathAttempt, "\0") === false) {
        $realFullPath = realpath($filePathAttempt);
        $message = ($realFullPath ? htmlspecialchars($realFullPath) : 'Path does not exist or is invalid');
    } else {
        // PHP 8+ realpath() throws ValueError on null bytes.
        // file_exists() etc. will treat null byte as part of filename.
        $message = 'Path contains null byte, realpath() not called or would fail. Filesystem functions will treat null as part of name.';
        // $realFullPath tetap null
    }
    echo "Resolved real path: " . $message . "\n\n";

    if ($realFullPath && file_exists($realFullPath) && is_file($realFullPath) && is_readable($realFullPath)) {
        echo "--- File Content Start ---\n";
        echo htmlspecialchars(file_get_contents($realFullPath));
        echo "\n--- File Content End ---";
    } else {
        echo "Error: File not found, not a file, or not readable at (potentially modified by null byte) resolved path.";
        
        $nullPos = strpos($userFile, "\0");
        if ($nullPos !== false) {
            $truncatedFilePart = substr($userFile, 0, $nullPos);
            $simulatedPathIfTruncated = $baseDir . $truncatedFilePart;
            echo "\n\n--- Simulation of pre-filesystem null byte truncation ---";
            echo "\nPath if input string was truncated at null byte: " . htmlspecialchars($simulatedPathIfTruncated);
            $realSimulatedPath = realpath($simulatedPathIfTruncated);
            echo "\nResolved real path (simulated truncation): " . ($realSimulatedPath ? htmlspecialchars($realSimulatedPath) : 'Path does not exist or is invalid');
            if ($realSimulatedPath && file_exists($realSimulatedPath) && is_file($realSimulatedPath) && is_readable($realSimulatedPath)) {
                echo "\n--- Simulated File Content Start ---\n";
                echo htmlspecialchars(file_get_contents($realSimulatedPath));
                echo "\n--- Simulated File Content End ---";
            } else {
                echo "\nSimulated truncated path also not found or readable.";
            }
        }
    }
} else {
    echo "Usage: ?file=<payload_with_null_byte%00>";
}
?>