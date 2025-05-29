<?php // tests/ObfuscatedMixedSlashesTraversalTest.php

namespace Tests;

class ObfuscatedMixedSlashesTraversalTest extends BaseVulnerableScriptTest
{
    public function testObfuscatedTraversalToSecretFile()
    {
        $scriptName = 'vuln_obfuscated_mixed_slashes_traversal.php';
        // Payload untuk keluar dari 'safe_dir' ke 'secret_dir'
        $payload = '..././.\\../secret_dir/secret.txt'; // Variasi obfuscation
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString($this->secretContent, $output, "Gagal via obfuscated. Output:\n" . $output);
        $expectedPathEnd = 'secret_dir' . DIRECTORY_SEPARATOR . 'secret.txt';
        $this->assertStringContainsString($expectedPathEnd, $output);
    }

    public function testMixedSlashesTraversalToSecretFile()
    {
        $scriptName = 'vuln_obfuscated_mixed_slashes_traversal.php';
        $payload = '..\\secret_dir/secret.txt'; // Kombinasi \ dan /
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString($this->secretContent, $output, "Gagal via mixed slashes. Output:\n" . $output);
        $expectedPathEnd = 'secret_dir' . DIRECTORY_SEPARATOR . 'secret.txt';
        $this->assertStringContainsString($expectedPathEnd, $output);
    }
}