<?php
// src/vuln_file_read.php
// WARNING: This script is intentionally vulnerable. Do NOT use in production.

$sandboxBase = __DIR__ . '/../vulnerable_files/safe_dir/'; // Intended base directory

if (isset($_GET['file'])) {
    $requestedFile = $_GET['file'];
    $finalPath = null;

    if (preg_match('/^([A-Za-z]:\\\\|\/)/', $requestedFile)) {
        $finalPath = $requestedFile;
    } else {
        $finalPath = $sandboxBase . $requestedFile;
    }

    $finalPath = str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $finalPath);
    $resolvedPath = realpath($finalPath);

    if ($resolvedPath && is_file($resolvedPath) && is_readable($resolvedPath)) {
        readfile($resolvedPath);
        exit;
    } elseif (!$resolvedPath && is_file($finalPath) && is_readable($finalPath)) {
        readfile($finalPath);
        exit;
    } else {
        header("HTTP/1.0 404 Not Found");
        echo "Error: File not found or not readable. Attempted: " . htmlspecialchars($finalPath);
        if ($resolvedPath && $resolvedPath !== $finalPath) {
            echo " | Resolved to: " . htmlspecialchars($resolvedPath);
        }
        exit;
    }
} else {
    echo "Usage: vuln_file_read.php?file=<filename>";
    exit;
}
?>