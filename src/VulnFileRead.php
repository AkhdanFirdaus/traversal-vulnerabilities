<?php

namespace App;

class VulnFileRead
{
    public function read($filename): string
    {
        // Deliberate lack of sanitization for path traversal simulation
        $base = __DIR__ . '/../vulnerable_files/';
        $fullPath = realpath($base . $filename);

        // Vulnerable logic — only checks that $fullPath starts with base
        if ($fullPath && str_starts_with($fullPath, realpath($base))) {
            return file_get_contents($fullPath);
        }

        return 'Access denied';
    }
}
