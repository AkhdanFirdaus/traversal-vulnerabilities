<?php // tests/ExtraDotsTraversalTest.php

namespace Tests;

class ExtraDotsTraversalTest extends BaseVulnerableScriptTest
{
    public function testExtraDotsAccessSecretFile()
    {
        $scriptName = 'vuln_extra_dots_traversal.php';
        $payload = '../secret_dir/secret.txt.........';
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $expectedSecretPathEnd = 'vulnerable_files' . DIRECTORY_SEPARATOR . 'secret_dir' . DIRECTORY_SEPARATOR . 'secret.txt';
        $expectedPayloadPathEndWithDots = 'vulnerable_files' . DIRECTORY_SEPARATOR . 'secret_dir' . DIRECTORY_SEPARATOR . 'secret.txt.........';


        if (str_contains(strtolower(PHP_OS), 'win')) {
            $this->assertStringContainsString($this->secretContent, $output, "Gagal via extra dots (Windows). Output:\n" . $output);
            // Di Windows, resolved path seharusnya TIDAK mengandung titik ekstra
            $this->assertStringContainsString($expectedSecretPathEnd, $output, "Resolved path di Windows salah. Output:\n" . $output);
            $this->assertStringNotContainsString($expectedSecretPathEnd . '.', $output, "Resolved path di Windows seharusnya tidak ada titik ekstra. Output:\n" . $output);
        } else {
            // Di Linux, file "secret.txt........." tidak sama dengan "secret.txt"
            $this->assertStringNotContainsString($this->secretContent, $output, "Konten rahasia tidak seharusnya terbaca (Linux). Output:\n" . $output);
            $this->assertStringContainsString("Error: File not found", $output, "Harus ada error file tidak ditemukan (Linux). Output:\n" . $output);

            // Cek apakah resolved path adalah invalid atau mengandung titik
            preg_match('/Resolved real path: (.*)/', $output, $matches);
            $resolvedPathInOutput = trim($matches[1] ?? '');

            if ($resolvedPathInOutput === 'Path does not exist or is invalid') {
                $this->assertTrue(true, "Path korrek tidak valid di Linux untuk titik ekstra.");
            } else {
                // Jika path ada, itu harus path DENGAN titik
                $this->assertStringEndsWith('.........', $resolvedPathInOutput, "Resolved path di Linux harusnya mengandung titik ekstra jika ada. Output:\n" . $output);
            }
        }
    }
}