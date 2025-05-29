<?php // tests/UnicodeTraversalTest.php

namespace Tests;

class UnicodeTraversalTest extends BaseVulnerableScriptTest
{
    public function testCanAccessSecretFileWithUnicodePercentUTraversal()
    {
        $scriptName = 'vuln_unicode_traversal.php';
        // Payload: ../secret_dir/secret.txt
        // . -> %u002e
        // / -> %u2216 (DIVISION SLASH) atau %u002f (SOLIDUS)
        // Kita gunakan %u2216 untuk menguji fleksibilitas dekoder
        $payload = '%u002e%u002e%u2216secret_dir%u2216secret.txt';
        $params = ['path_unicode' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->secretContent, $output, "Gagal via Unicode. Output:\n" . $output);
        $this->assertStringContainsString("Raw Unicode Input: " . htmlspecialchars($payload), $output);

        // Path yang diharapkan setelah custom_unsafe_unicode_decoder (sebelum normalisasi slash internal skrip)
        $expectedDecodedByFunc = ".." . "\u{2216}" . "secret_files" . "\u{2216}" . "secret.txt";
        $this->assertStringContainsString("Decoded by custom_unsafe_unicode_decoder: " . htmlspecialchars($expectedDecodedByFunc), $output);

        // Path yang diharapkan setelah normalisasi slash internal skrip
        $expectedNormalizedPath = ".." . DIRECTORY_SEPARATOR . "secret_files" . DIRECTORY_SEPARATOR . "secret.txt";
        $this->assertStringContainsString("Normalized Decoded Path (for file access): " . htmlspecialchars($expectedNormalizedPath), $output);
    }
}