<?php
// Vulnerable to: ../secret_files/secret.txt%00anything.jpg
// Example URL: vuln_null_byte_traversal.php?file=../secret_files/secret.txt%00fake_image.jpg
// PHP's $_GET will URL-decode %00 to the actual null byte character (\0).

header('Content-Type: text/plain');
$baseDir = 'public_files/';
$allowedExtension = '.jpg'; // App might try to enforce an extension

if (isset($_GET['file'])) {
    $userFile = $_GET['file']; // Contains the actual null byte if %00 was in URL

    // Naive check for extension (bypassed by null byte if vulnerable)
    // In modern PHP, strpos($userFile, "\0") would find the null byte.
    // The vulnerability was that C-based file functions would stop at \0.
    $filePath = $baseDir . $userFile;

    // If an application *also* tries to append an extension after checking,
    // the null byte would terminate the path before this appended extension.
    // $filePath = $baseDir . $userFile_potentially_truncated_by_null . $allowedExtension;

    echo "User input (file): " . bin2hex($userFile) . " (hex representation)\n";
    echo "Attempting to read: " . $filePath . "\n";
    echo "Resolved real path: " . realpath($filePath) . "\n\n";

    // For file_get_contents in modern PHP, it will likely look for a file
    // literally named "secret.txt\0fake_image.jpg", which won't exist.
    // To truly show the old vulnerability, one might need an older PHP
    // or a different function that is still affected (e.g. calling external command).
    if (file_exists($filePath) && is_readable($filePath)) {
        echo file_get_contents($filePath);
    } else {
        echo "Error: File not found or not readable. Modern PHP file functions are generally null-byte safe regarding path truncation.";
        echo "\nIf this were an older system or a different file handling mechanism,";
        echo "\nthe path might have been truncated at the null byte.";

        // Simulate truncation for demonstration if desired for testing logic elsewhere
        $nullPos = strpos($userFile, "\0");
        if ($nullPos !== false) {
            $truncatedFile = substr($userFile, 0, $nullPos);
            $simulatedPath = $baseDir . $truncatedFile;
            echo "\n\nSimulated path if truncated at null byte: " . $simulatedPath;
            echo "\nResolved real path (simulated): " . realpath($simulatedPath);
            if (file_exists($simulatedPath) && is_readable($simulatedPath)) {
                echo "\nContent if truncated: \n";
                echo file_get_contents($simulatedPath);
            }
        }
    }
} else {
    echo "Usage: ?file=<path_with_null_byte%00extension>";
}
?>