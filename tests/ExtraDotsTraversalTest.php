<?php // tests/ExtraDotsTraversalTest.php

namespace Tests;

class ExtraDotsTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * Menguji traversal menggunakan titik ekstra di akhir nama file.
     * @see CWE-35 Path Traversal: 'filename...' (Trailing Dots)
     */
    public function testExtraDotsAccessSecretFile()
    {
        $scriptName = 'vuln_extra_dots_traversal.php';
        $payload = '../secret_dir/secret.txt.........';
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);
        $fullExpectedResolvedPathNoDots = realpath($this->baseVulnerableFilesPath . '/secret_dir/secret.txt');

        if (str_contains(strtolower(PHP_OS), 'win')) {
            $this->assertStringContainsString(htmlspecialchars($this->secretContent), $output, "Gagal via extra dots (Windows). Output:\n" . $output);
            $this->assertStringContainsString("Resolved real path: " . htmlspecialchars($fullExpectedResolvedPathNoDots), $output, "Resolved path di Windows salah. Output:\n" . $output);
        } else { // Linux dan OS lain yang sensitif terhadap trailing dots
            $this->assertStringNotContainsString(htmlspecialchars($this->secretContent), $output, "Konten rahasia tidak seharusnya terbaca (Non-Windows). Output:\n" . $output);
            $this->assertStringContainsString("Error: File not found", $output, "Harus ada error file tidak ditemukan (Non-Windows). Output:\n" . $output);
            
            // Di Linux, realpath dari path dengan titik ekstra akan berbeda atau invalid
            preg_match('/Resolved real path: (.*)/', $output, $matches);
            $resolvedPathInOutput = trim($matches[1] ?? '');
            if ($resolvedPathInOutput !== 'Path does not exist or is invalid') {
                 $this->assertNotEquals($fullExpectedResolvedPathNoDots, $resolvedPathInOutput, "Resolved path di Non-Windows seharusnya tidak sama dengan path tanpa titik.");
                 $this->assertStringEndsWith('.........', $resolvedPathInOutput, "Resolved path di Non-Windows seharusnya mengandung titik ekstra jika path valid.");
            } else {
                $this->assertEquals('Path does not exist or is invalid', $resolvedPathInOutput);
            }
        }
    }
}