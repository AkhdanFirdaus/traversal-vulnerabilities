<?php // tests/EmbeddedTraversalTest.php

namespace Tests;

class EmbeddedTraversalTest extends BaseVulnerableScriptTest
{
    private function ensureTestSubdirectoryExists(string $subDirName): string {
        $safeDirPath = realpath($this->baseVulnerableFilesPath . '/safe_dir/');
        if ($safeDirPath === false) {
            $this->markTestSkipped("Direktori safe_dir tidak ditemukan untuk membuat subdirektori tes.");
        }
        $fullPath = $safeDirPath . DIRECTORY_SEPARATOR . $subDirName;
        if (!is_dir($fullPath)) {
            if (!mkdir($fullPath, 0777, true) && !is_dir($fullPath)) { // Tambahkan !is_dir() untuk race condition
                 $this->fail("Gagal membuat direktori tes sementara: $fullPath");
            }
        }
        return $subDirName;
    }

    private function cleanupTestSubdirectory(string $subDirName): void {
        $safeDirPath = realpath($this->baseVulnerableFilesPath . '/safe_dir/');
        if ($safeDirPath === false) return; // Tidak ada yang perlu dibersihkan jika safe_dir tidak ada

        $fullPath = $safeDirPath . DIRECTORY_SEPARATOR . $subDirName;
        if (is_dir($fullPath)) {
            // Hanya hapus jika direktori tersebut kosong, untuk keamanan.
            // Jika tes membuat file di dalamnya, tes itu yang harus menghapusnya dulu.
            if (count(scandir($fullPath)) == 2) { // . dan ..
                 @rmdir($fullPath);
            }
        }
    }

    /**
     * Menguji traversal yang disisipkan di tengah path.
     * @see CWE-31 Path Traversal: 'dir/../../filedir' (Mid-Path)
     * @see CWE-27 Path Traversal: 'dir/../filedir' (Folder Up One Level)
     */
    public function testMidPathTraversalToSecretFile()
    {
        $scriptName = 'vuln_embedded_traversal.php';
        $imageDir = $this->ensureTestSubdirectoryExists('images_test_midpath');

        // Dari .../safe_dir/, masuk ke 'images_test_midpath', lalu keluar dua level, lalu ke 'secret_dir'
        $payload = $imageDir . '/../../secret_dir/secret.txt';
        $params = ['resource' => $payload];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString(htmlspecialchars($this->secretContent), $output, "Gagal via mid-path. Output:\n" . $output);
        
        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/secret_dir/secret.txt');
        $this->assertStringContainsString("Resolved real path: " . htmlspecialchars($fullExpectedResolvedPath), $output);

        $this->cleanupTestSubdirectory('images_test_midpath');
    }

    /**
     * Menguji traversal menggunakan normalisasi 'dir/..'.
     * @see CWE-32 Path Traversal: 'dir/dir/../filedir' (dir/.. Normalization)
     * @see CWE-27 Path Traversal: 'dir/../filedir' (Folder Up One Level)
     */
    public function testDirNormalizationToSecretFile()
    {
        $scriptName = 'vuln_embedded_traversal.php';
        // BaseVulnerableScriptTest::setUp() seharusnya sudah memverifikasi/membuat vulnerable_files/safe_dir/modules/
        // Jika belum, pastikan itu ada.
        $moduleDir = 'modules'; // Subdirektori yang ada di dalam safe_dir

        // Dari .../safe_dir/, masuk ke 'modules', lalu keluar dua level, lalu ke 'secret_dir'
        $payload = $moduleDir . '/../../secret_dir/secret.txt';
        $params = ['resource' => $payload];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString(htmlspecialchars($this->secretContent), $output, "Gagal via dir/.. normalization. Output:\n" . $output);

        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/secret_dir/secret.txt');
        $this->assertStringContainsString("Resolved real path: " . htmlspecialchars($fullExpectedResolvedPath), $output);
    }
}