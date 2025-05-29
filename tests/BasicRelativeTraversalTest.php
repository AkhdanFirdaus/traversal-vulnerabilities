<?php // tests/BasicRelativeTraversalTest.php

namespace Tests;

class BasicRelativeTraversalTest extends BaseVulnerableScriptTest
{
    public function testCanAccessSecretFileWithRelativeTraversal()
    {
        $scriptName = 'vuln_basic_relative_traversal.php';
        // Payload untuk keluar dari 'vulnerable_files/safe_dir/' ke 'vulnerable_files/secret_dir/'
        $payload = '../secret_dir/secret.txt';
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->secretContent, $output, "Gagal mengambil konten rahasia. Output:\n" . $output);
        $this->assertStringContainsString("User Input ('file'): " . htmlspecialchars($payload), $output);

        // Verifikasi bahwa path yang di-resolve benar
        $expectedResolvedPathEnd = 'vulnerable_files' . DIRECTORY_SEPARATOR . 'secret_dir' . DIRECTORY_SEPARATOR . 'secret.txt';
        $this->assertStringContainsString($expectedResolvedPathEnd, $output, "Path yang di-resolve tidak mengandung target yang benar. Output:\n" . $output);
    }

    public function testAttemptsToAccessSimulatedEtcPasswd()
    {
        $scriptName = 'vuln_basic_relative_traversal.php';
        // Dari 'vulnerable_files/safe_dir/' ke 'vulnerable_files/etc/passwd'
        $payload = '../etc/passwd';
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->etcPasswdContent, $output, "Gagal mengambil konten passwd yang disimulasikan. Output:\n" . $output);
        $expectedResolvedPathEnd = 'vulnerable_files' . DIRECTORY_SEPARATOR . 'etc' . DIRECTORY_SEPARATOR . 'passwd';
        $this->assertStringContainsString($expectedResolvedPathEnd, $output, "Path passwd yang di-resolve tidak benar. Output:\n" . $output);
    }
}