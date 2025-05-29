<?php
// Vulnerable to: ../admin, ../config (as parts of a path)
// Example URL: vuln_specific_dir_traversal.php?module=../secret_files/admin/panel.php
// Example URL: vuln_specific_dir_traversal.php?module=../secret_files/config/db.php

header('Content-Type: text/plain');
$modulesBaseDir = 'public_files/modules/'; // e.g., public_files/modules/gallery/

if (isset($_GET['module'])) {
    $modulePath = $_GET['module'];
    // Vulnerability: Assumes $modulePath is just 'gallery', 'profile' etc.
    // but an attacker can use '../' to break out of 'public_files/modules/'
    // and then target specific known paths.
    $fullPath = $modulesBaseDir . $modulePath; // Path like 'public_files/modules/' . '../secret_files/admin/panel.php'

    echo "Attempting to load module from: " . $fullPath . "\n";
    echo "Resolved real path: " . realpath($fullPath) . "\n\n";

    if (file_exists($fullPath)) {
        include $fullPath;
    } else {
        echo "Error: Module not found at '{$fullPath}'.";
    }
} else {
    echo "Usage: ?module=<module_path>";
}
?>