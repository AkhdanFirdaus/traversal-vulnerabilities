<?php // tests/NullByteTraversalTest.php

namespace Tests;

class NullByteTraversalTest extends BaseVulnerableScriptTest
{
    public function testNullByteAttemptToAccessSecretFile()
    {
        $scriptName = 'vuln_null_byte_traversal.php';
        // Payload: ../secret_dir/secret.txt\0fake.jpg
        $payload = '../secret_dir/secret.txt' . "\0" . 'fake.jpg'; // PHPUnit akan mengirim \0 secara literal
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);

        // Pada PHP modern, file_get_contents tidak akan terpotong oleh null byte di tengah nama file.
        // Jadi, kita mengharapkan file "secret.txt\0fake.jpg" tidak ditemukan.
        $this->assertStringContainsString("Error: File not found, not a file, or not readable at resolved path.", $output, "Output tidak menunjukkan error file tidak ditemukan seperti yang diharapkan untuk null byte di PHP modern. Output:\n" . $output);

        // Verifikasi bahwa bagian simulasi dari skrip (jika null byte ada) mencoba path yang benar
        // dan membaca konten rahasia.
        $this->assertStringContainsString("--- Simulation of pre-filesystem null byte truncation ---", $output, "Bagian simulasi null byte tidak ditemukan. Output:\n" . $output);

        $expectedSimulatedPathEnd = 'vulnerable_files' . DIRECTORY_SEPARATOR . 'secret_dir' . DIRECTORY_SEPARATOR . 'secret.txt';
        $this->assertStringContainsString($expectedSimulatedPathEnd, $output, "Path simulasi yang di-resolve tidak benar. Output:\n" . $output);
        $this->assertStringContainsString($this->secretContent, $output, "Simulasi null byte truncation gagal mengambil konten rahasia. Output:\n" . $output);
    }
}