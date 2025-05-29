<?php // tests/DoubleEncodedTraversalTest.php

namespace Tests;

class DoubleEncodedTraversalTest extends BaseVulnerableScriptTest
{
    public function testCanAccessSecretFileWithDoubleEncoding()
    {
        $scriptName = 'vuln_double_encoded_traversal.php';
        // Target: ../secret_dir/secret.txt
        // Single encode: %2e%2e%2fsecret_dir%2fsecret.txt
        // Double encode (hanya bagian traversal untuk kesederhanaan, atau seluruhnya):
        // %252e%252e%252f -> ../
        // secret_dir -> secret_dir (atau %73%65%63%72%65%74%5f%64%69%72)
        // %252f -> /
        $payload = '%252e%252e%252fsecret_dir%252fsecret.txt'; // ../secret_dir/secret.txt
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->secretContent, $output, "Gagal via double encoding. Output:\n" . $output);
        $this->assertStringContainsString("Original \$_GET['file'] (singly decoded by PHP): " . htmlspecialchars('%2e%2e%2fsecret_dir%2fsecret.txt'), $output);
        $this->assertStringContainsString("After script's urldecode() (doubly decoded): " . htmlspecialchars('../secret_dir/secret.txt'), $output);
    }
}