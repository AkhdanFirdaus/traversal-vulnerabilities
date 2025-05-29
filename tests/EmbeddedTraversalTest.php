<?php // tests/EmbeddedTraversalTest.php

namespace Tests;

class EmbeddedTraversalTest extends BaseVulnerableScriptTest
{
    // Helper untuk memastikan subdirektori ada untuk tes ini, jika belum dibuat di Base
    private function ensureTestSubdirectoryExists(string $subDirName): string {
        $fullPath = realpath(__DIR__ . '/../vulnerable_files/safe_dir/') . DIRECTORY_SEPARATOR . $subDirName;
        if (!is_dir($fullPath)) {
            mkdir($fullPath, 0777, true);
        }
        return $subDirName; // Mengembalikan nama subdirektori untuk digunakan dalam payload
    }

    private function cleanupTestSubdirectory(string $subDirName): void {
        $fullPath = realpath(__DIR__ . '/../vulnerable_files/safe_dir/') . DIRECTORY_SEPARATOR . $subDirName;
        if (is_dir($fullPath)) {
            @rmdir($fullPath); // Hanya rmdir jika kosong
        }
    }

    public function testMidPathTraversalToSecretFile()
    {
        $scriptName = 'vuln_embedded_traversal.php';
        $imageDir = $this->ensureTestSubdirectoryExists('images_test'); // Buat dir 'images_test' di dalam safe_dir

        // Dari 'vulnerable_files/safe_dir/', masuk ke 'images_test', lalu keluar dua level, lalu ke 'secret_dir'
        $payload = $imageDir . '/../../secret_dir/secret.txt';
        $params = ['resource' => $payload];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString($this->secretContent, $output, "Gagal via mid-path. Output:\n" . $output);
        $this->cleanupTestSubdirectory('images_test');
    }

    public function testDirNormalizationToSecretFile()
    {
        $scriptName = 'vuln_embedded_traversal.php';
        // BaseVulnerableScriptTest::setUp sudah membuat vulnerable_files/safe_dir/modules/
        // Kita akan menggunakan 'modules' sebagai dir yang "sah" untuk dir/..
        // Dari 'vulnerable_files/safe_dir/', masuk ke 'modules', lalu keluar dua level, lalu ke 'secret_dir'
        $payload = 'modules/../../secret_dir/secret.txt';
        $params = ['resource' => $payload];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString($this->secretContent, $output, "Gagal via dir/.. normalization. Output:\n" . $output);
    }
}