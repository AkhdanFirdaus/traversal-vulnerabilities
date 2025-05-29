<?php // tests/NullByteTraversalTest.php

namespace Tests;

class NullByteTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * Menguji injeksi null byte.
     * @see CWE-30 Path Traversal: '%00' (Null Byte Injection)
     */
    public function testNullByteAttemptToAccessSecretFile()
    {
        $scriptName = 'vuln_null_byte_traversal.php';
        $payload = '../secret_dir/secret.txt' . "\0" . 'fake.jpg';
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);

        // PHP 8+ realpath() akan throw ValueError, atau kita skip. file_exists() akan gagal.
        $this->assertStringNotContainsString("--- File Content Start ---", $output, "Konten rahasia seharusnya tidak terbaca langsung saat null byte ada. Output:\n" . $output);
        $this->assertStringContainsString("Path contains null byte, realpath() not called or would fail.", $output, "Skrip seharusnya mendeteksi null byte. Output:\n" . $output);
        $this->assertStringContainsString("Error: File not found", $output, "Output tidak menunjukkan error file tidak ditemukan. Output:\n" . $output);

        // Verifikasi bagian simulasi
        if (str_contains($output, "--- Simulation of pre-filesystem null byte truncation ---")) {
            $fullExpectedSimulatedPath = realpath($this->baseVulnerableFilesPath . '/secret_dir/secret.txt');
            $this->assertStringContainsString("Resolved real path (simulated truncation): " . htmlspecialchars($fullExpectedSimulatedPath), $output, "Path simulasi yang di-resolve tidak benar. Output:\n" . $output);
            $this->assertStringContainsString(htmlspecialchars($this->secretContent), $output, "Simulasi null byte truncation gagal mengambil konten rahasia. Output:\n" . $output);
        } else {
            $this->fail("Bagian simulasi null byte tidak ditemukan dalam output.");
        }
    }
}
