<?php // tests/ObfuscatedMixedSlashesTraversalTest.php

namespace Tests;

class ObfuscatedMixedSlashesTraversalTest extends BaseVulnerableScriptTest
{
    public function testObfuscatedTraversalToSecretFile()
    {
        $scriptName = 'vuln_obfuscated_mixed_slashes_traversal.php';
        // $baseDir adalah .../safe_dir/
        // Payload: ..././../secret_dir/secret.txt
        // Ini akan resolve ke .../safe_dir/..././../secret_dir/secret.txt
        // yang seharusnya menjadi .../vulnerable_files/secret_dir/secret.txt
        $params = ['file' => '..././../secret_dir/secret.txt'];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString($this->secretContent, $output, "Gagal mengambil konten rahasia dengan obfuscated traversal.");
    }

    public function testMixedSlashesTraversalToSecretFile()
    {
        $scriptName = 'vuln_obfuscated_mixed_slashes_traversal.php';
        // Payload: ..\\secret_dir/secret.txt
        $params = ['file' => '..\\secret_dir/secret.txt'];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString($this->secretContent, $output, "Gagal mengambil konten rahasia dengan mixed slashes traversal.");
    }
}