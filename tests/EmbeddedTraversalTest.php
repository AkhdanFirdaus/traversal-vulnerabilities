<?php // tests/EmbeddedTraversalTest.php

namespace Tests;

class EmbeddedTraversalTest extends BaseVulnerableScriptTest
{
    public function testMidPathTraversalToSecretFile()
    {
        // Pola seperti: images/../../secret_dir/secret.txt
        $scriptName = 'vuln_embedded_traversal.php';
        // $baseDir skrip adalah .../safe_dir/
        // Payload 'images/../../secret_dir/secret.txt' akan menjadi:
        // .../safe_dir/images/../../secret_dir/secret.txt
        // Ini akan resolve ke .../vulnerable_files/secret_dir/secret.txt
        $params = ['resource' => 'images/../../secret_dir/secret.txt'];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString($this->secretContent, $output, "Gagal mengambil konten rahasia dengan mid-path traversal.");
    }

    public function testDirNormalizationToSecretFile()
    {
        // Pola seperti: legit.txt/../secret_dir/secret.txt (mengasumsikan legit.txt ada di safe_dir)
        // atau dummy_dir/../secret_dir/secret.txt
        $scriptName = 'vuln_embedded_traversal.php';
        // $baseDir skrip adalah .../safe_dir/
        // Payload 'legit.txt/../secret_dir/secret.txt' akan menjadi:
        // .../safe_dir/legit.txt/../secret_dir/secret.txt
        // Ini akan resolve ke .../vulnerable_files/secret_dir/secret.txt
        $params = ['resource' => 'legit.txt/../secret_dir/secret.txt'];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString($this->secretContent, $output, "Gagal mengambil konten rahasia dengan dir/.. normalization.");
    }
}