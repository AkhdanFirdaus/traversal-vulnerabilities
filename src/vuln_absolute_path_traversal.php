<?php // src/vuln_absolute_path_traversal.php

header('Content-Type: text/plain; charset=utf-8');

$scriptSafeBaseDir = realpath(__DIR__ . '/../vulnerable_files/safe_dir/') . DIRECTORY_SEPARATOR;
$simulatedFSRoot = realpath(__DIR__ . '/../vulnerable_files'); // Root untuk path absolut yang disimulasikan

if (isset($_GET['path'])) {
    $userInputPath = $_GET['path'];
    $isAbsoluteUnix = str_starts_with($userInputPath, '/');
    $isAbsoluteWindows = preg_match('/^[A-Za-z]:(\\\\|\/)/', $userInputPath) === 1;

    $finalPathToRead = null;
    $effectivePathDebug = '';

    if ($isAbsoluteUnix || $isAbsoluteWindows) {
        if ($isAbsoluteUnix) {
            $effectivePathDebug = $simulatedFSRoot . $userInputPath;
        } else { // Windows
            $pathWithoutDrive = preg_replace('/^[A-Za-z]:(\\\\|\/)?/', '', $userInputPath);
            $effectivePathDebug = $simulatedFSRoot . DIRECTORY_SEPARATOR . str_replace(['\\', '/'], DIRECTORY_SEPARATOR, $pathWithoutDrive);
        }
        $finalPathToRead = realpath($effectivePathDebug);
        echo "Input appears to be an absolute path (simulated access).\n";
    } else {
        $effectivePathDebug = $scriptSafeBaseDir . $userInputPath;
        $finalPathToRead = realpath($effectivePathDebug);
        echo "Input appears to be a relative path.\n";
    }

    echo "User input path: " . htmlspecialchars($userInputPath) . "\n";
    echo "Effective target path before realpath: " . htmlspecialchars($effectivePathDebug) . "\n";
    echo "Resolved real path (final attempt): " . ($finalPathToRead ? htmlspecialchars($finalPathToRead) : 'Path does not exist or is invalid') . "\n\n";

    if ($finalPathToRead && file_exists($finalPathToRead) && is_readable($finalPathToRead) && is_file($finalPathToRead)) {
        echo "--- File Content Start ---\n";
        echo htmlspecialchars(file_get_contents($finalPathToRead));
        echo "\n--- File Content End ---";
    } else {
        echo "Error: File not found, not a file, or not readable at final path.";
    }
} else {
    echo "Usage: ?path=<absolute_or_relative_path>";
}
?>