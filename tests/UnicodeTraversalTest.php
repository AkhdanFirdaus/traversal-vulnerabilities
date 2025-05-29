<?php // tests/UnicodeTraversalTest.php

namespace Tests;

class UnicodeTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * Menguji traversal menggunakan encoding Unicode (%uXXXX).
     * @see CWE-29 Path Traversal: '%u002E%u002E%u2215' (Unicode Encoded)
     */
    public function testCanAccessSecretFileWithUnicodePercentUTraversal()
    {
        $scriptName = 'vuln_unicode_traversal.php';
        $payload = '%u002e%u002e%u2216secret_dir%u2216secret.txt'; // Menggunakan U+2216 DIVISION SLASH
        $params = ['path_unicode' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString(htmlspecialchars($this->secretContent), $output, "Gagal via Unicode. Output:\n" . $output);
        
        $expectedDecodedByFunc = ".." . "\u{2216}" . "secret_dir" . "\u{2216}" . "secret.txt";
        $this->assertStringContainsString("Decoded by custom_unsafe_unicode_decoder: " . htmlspecialchars($expectedDecodedByFunc), $output);

        $expectedNormalizedPath = ".." . DIRECTORY_SEPARATOR . "secret_dir" . DIRECTORY_SEPARATOR . "secret.txt";
        $this->assertStringContainsString("Normalized Decoded Path (for file access): " . htmlspecialchars($expectedNormalizedPath), $output);

        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/secret_dir/secret.txt');
        $this->assertStringContainsString("Resolved real path: " . htmlspecialchars($fullExpectedResolvedPath), $output);
    }
}
