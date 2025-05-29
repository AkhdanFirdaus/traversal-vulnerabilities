<?php // src/vuln_specific_dir_traversal.php

header('Content-Type: text/plain; charset=utf-8');

// Basis direktori modul yang "sah".
$modulesBaseDir = realpath(__DIR__ . '/../vulnerable_files/safe_dir/modules/') . DIRECTORY_SEPARATOR;

if (isset($_GET['module_name'])) {
    $userModuleName = $_GET['module_name']; // Misal: "public_module.php" atau payload jahat

    // Kerentanan: Path langsung digabungkan.
    $modulePath = $modulesBaseDir . $userModuleName;

    echo "Modules Base Directory: " . htmlspecialchars($modulesBaseDir) . "\n";
    echo "User Module Input: " . htmlspecialchars($userModuleName) . "\n";
    echo "Attempting to load module from (constructed path): " . htmlspecialchars($modulePath) . "\n";

    $realModulePath = realpath($modulePath);
    echo "Resolved real path: " . ($realModulePath ? htmlspecialchars($realModulePath) : 'Path does not exist or is invalid') . "\n\n";

    if ($realModulePath && file_exists($realModulePath) && is_file($realModulePath) && is_readable($realModulePath)) {
        echo "--- Module Content Start ---\n";
        echo htmlspecialchars(file_get_contents($realModulePath));
        echo "\n--- Module Content End ---";
    } else {
        echo "Error: Module not found, not a file, or not readable at resolved path.";
    }
} else {
    echo "Usage: ?module_name=<module_filename.php>";
}
?>