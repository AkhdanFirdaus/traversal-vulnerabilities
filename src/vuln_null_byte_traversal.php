<?php // src/vuln_null_byte_traversal.php

header('Content-Type: text/plain; charset=utf-8');

$baseDir = realpath(__DIR__ . '/../vulnerable_files/safe_dir/') . DIRECTORY_SEPARATOR;
$enforcedExtension = ".jpg"; // Aplikasi mungkin mencoba menambahkan ekstensi.

if (isset($_GET['file'])) {
    $userFile = $_GET['file']; // Input dari pengguna, sudah di-URL-decode oleh PHP (%00 -> \0)

    // Potensi kerentanan jika logika aplikasi seperti ini:
    // 1. User menyediakan "path/ke/file\0jahat.jpg"
    // 2. Aplikasi mungkin memeriksa ekstensi pada $userFile (yang masih mengandung \0)
    // 3. Aplikasi kemudian MUNGKIN memproses bagian sebelum \0 untuk operasi file.

    // Path yang akan digunakan, mungkin dengan ekstensi yang dipaksakan
    // Jika $userFile sudah ada null byte, $enforcedExtension akan diabaikan oleh fungsi C lama.
    $filePathAttempt = $baseDir . $userFile; // Jika file tidak diakhiri dengan .jpg
    if (substr($userFile, -strlen($enforcedExtension)) !== $enforcedExtension) {
        // $filePathAttempt = $baseDir . $userFile . $enforcedExtension; // Logika ini salah jika ada null byte
    }


    echo "Base Directory: " . htmlspecialchars($baseDir) . "\n";
    echo "User Input ('file') (hex): " . bin2hex($userFile) . "\n"; // Tampilkan hex untuk melihat null byte
    echo "Attempting to access (raw constructed path): " . htmlspecialchars($filePathAttempt) . "\n";

    $realFullPath = realpath($filePathAttempt); // realpath juga umumnya null-byte safe di PHP modern
    echo "Resolved real path: " . ($realFullPath ? htmlspecialchars($realFullPath) : 'Path does not exist or is invalid') . "\n\n";

    if ($realFullPath && file_exists($realFullPath) && is_file($realFullPath) && is_readable($realFullPath)) {
        echo "--- File Content Start ---\n";
        echo htmlspecialchars(file_get_contents($realFullPath));
        echo "\n--- File Content End ---";
        echo "\nNote: File found, modern PHP's file_get_contents might not have truncated at null byte if present in filename itself.";
    } else {
        echo "Error: File not found, not a file, or not readable at resolved path.";
        echo "\nModern PHP file functions are generally null-byte safe regarding path truncation for a given string.";

        // Simulasi bagaimana null byte BISA mempengaruhi path JIKA DIPROSES SEBELUMNYA
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