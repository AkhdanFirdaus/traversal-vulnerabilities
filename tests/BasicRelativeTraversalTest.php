<?php // tests/BasicRelativeTraversalTest.php

namespace Tests; // Namespace diperbarui

// BaseVulnerableScriptTest ada di namespace yang sama
// use Tests\BaseVulnerableScriptTest; // Tidak perlu jika di namespace yang sama

class BasicRelativeTraversalTest extends BaseVulnerableScriptTest
{
    public function testCanAccessSecretFileWithBasicTraversal()
    {
        $scriptName = 'vuln_basic_relative_traversal.php';
        // Skrip di src/vuln_basic_relative_traversal.php memiliki $baseDir = realpath(__DIR__ . '/../vulnerable_files/safe_dir/')
        // Untuk keluar dari 'safe_dir/' dan masuk ke 'secret_dir/', payloadnya adalah '../secret_dir/secret.txt'
        $params = ['file' => '../secret_dir/secret.txt'];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->secretContent, $output, "Gagal mengambil konten rahasia menggunakan traversal dasar.");

        // Verifikasi bahwa path yang di-resolve menargetkan file secret.txt di dalam secret_dir
        $expectedResolvedPathFragment = DIRECTORY_SEPARATOR . 'vulnerable_files' . DIRECTORY_SEPARATOR . 'secret_dir' . DIRECTORY_SEPARATOR . 'secret.txt';
        $this->assertStringContainsString($expectedResolvedPathFragment, $output, "Path yang di-resolve sepertinya tidak menargetkan file rahasia dengan benar.");
    }

    public function testAttemptsToAccessSimulatedEtcPasswd()
    {
        $scriptName = 'vuln_basic_relative_traversal.php';
        // Dari vulnerable_files/safe_dir/, payloadnya adalah '../etc/passwd' untuk mencapai vulnerable_files/etc/passwd
        $params = ['file' => '../etc/passwd'];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->etcPasswdContent, $output, "Gagal mengambil konten /etc/passwd yang disimulasikan.");
        $expectedResolvedPathFragment = DIRECTORY_SEPARATOR . 'vulnerable_files' . DIRECTORY_SEPARATOR . 'etc' . DIRECTORY_SEPARATOR . 'passwd';
        $this->assertStringContainsString($expectedResolvedPathFragment, $output);
    }
}