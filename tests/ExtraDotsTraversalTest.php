<?php // tests/ExtraDotsTraversalTest.php

namespace Tests;

class ExtraDotsTraversalTest extends BaseVulnerableScriptTest
{
    public function testExtraDotsAccessSecretFile()
    {
        $scriptName = 'vuln_extra_dots_traversal.php';
        $payload = '../secret_dir/secret.txt.........'; // Trailing dots
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $expectedResolvedPathFragmentForSecret = DIRECTORY_SEPARATOR . 'vulnerable_files' . DIRECTORY_SEPARATOR . 'secret_dir' . DIRECTORY_SEPARATOR . 'secret.txt';

        if (str_contains(strtolower(PHP_OS), 'win')) {
            $this->assertStringContainsString($this->secretContent, $output, "Gagal mengambil konten rahasia dengan extra dots (Windows).");
            // Cek apakah realpath menghilangkan titik-titik
            // Output skrip yang rentan menyertakan "Resolved real path: ..."
            // Kita mengharapkan path ini tidak memiliki titik-titik ekstra
            preg_match('/Resolved real path: (.*)/', $output, $matches);
            $resolvedPathInOutput = $matches[1] ?? '';

            // Pastikan resolved path menunjuk ke file tanpa titik ekstra
            $this->assertEquals(realpath(__DIR__ . '/../vulnerable_files/secret_dir/secret.txt'), $resolvedPathInOutput, "Path yang di-resolve di Windows seharusnya tanpa titik ekstra.");

        } else {
            // Di Linux, file "secret.txt........." seharusnya tidak ditemukan (kecuali memang ada)
            // dan tidak sama dengan "secret.txt".
            $this->assertStringNotContainsString($this->secretContent, $output, "Konten rahasia seharusnya tidak terbaca dengan extra dots di Linux (kecuali file bernama 'secret.txt.........' ada).");
            $this->assertStringContainsString("Error: File not found or not readable.", $output, "Seharusnya ada error file tidak ditemukan di Linux untuk extra dots.");
            
            // Verifikasi bahwa resolved path di Linux MUNGKIN masih mengandung titik atau menjadi false
            preg_match('/Resolved real path: (.*)/', $output, $matches);
            $resolvedPathInOutput = $matches[1] ?? '';
            if ($resolvedPathInOutput !== 'Path does not exist or is invalid') {
                 // Jika path ada, pastikan itu BUKAN path ke file tanpa titik (kecuali file aslinya bernama dengan titik)
                $this->assertNotEquals(realpath(__DIR__ . '/../vulnerable_files/secret_dir/secret.txt'), $resolvedPathInOutput, "Resolved path di Linux seharusnya tidak sama dengan file tanpa titik, kecuali jika path itu sendiri invalid.");
            } else {
                $this->assertEquals('Path does not exist or is invalid', $resolvedPathInOutput, "Resolved path di Linux seharusnya invalid untuk file dengan titik ekstra yang tidak ada.");
            }
        }
    }
}