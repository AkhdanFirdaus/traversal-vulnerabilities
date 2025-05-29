<?php // tests/NullByteTraversalTest.php

namespace Tests;

class NullByteTraversalTest extends BaseVulnerableScriptTest
{
    public function testNullByteAttemptToAccessSecretFile()
    {
        $scriptName = 'vuln_null_byte_traversal.php';
        // Payload: ../secret_dir/secret.txt%00fake.jpg
        // Tes PHPUnit akan mengirimkan karakter null byte (\0) secara langsung.
        $payload = '../secret_dir/secret.txt' . "\0" . 'fake_image.jpg';
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);

        // Pada PHP modern, file_get_contents biasanya aman dari path truncation null byte.
        // Skrip yang rentan memiliki logika untuk menampilkan ini.
        $this->assertStringContainsString("Error: File not found or not readable. Modern PHP file functions are generally null-byte safe", $output);

        // Cek apakah bagian simulasi dari skrip (jika ada dan diaktifkan) bekerja
        // Ini bergantung pada implementasi di vuln_null_byte_traversal.php
        $expectedSimulatedPath = DIRECTORY_SEPARATOR . 'vulnerable_files' . DIRECTORY_SEPARATOR . 'safe_dir' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'secret_dir' . DIRECTORY_SEPARATOR . 'secret.txt';
        // Normalisasi path untuk perbandingan yang lebih andal
        $normalizedExpectedSimulatedPath = realpath(__DIR__ . '/../vulnerable_files/secret_dir/secret.txt');


        if (str_contains($output, "Simulated path if truncated at null byte:")) {
             // Pastikan path yang disimulasikan benar
            $this->assertStringContainsString($normalizedExpectedSimulatedPath, $output, "Path simulasi null byte tidak sesuai harapan.");
            // Jika simulasi berhasil membaca file:
            if(str_contains($output, "Content if truncated:")) {
                 $this->assertStringContainsString($this->secretContent, $output, "Simulasi null byte truncation tidak mengungkapkan konten rahasia.");
            }
        }
    }
}