<?php // tests/DoubleEncodedTraversalTest.php

namespace Tests;

class DoubleEncodedTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * Menguji traversal menggunakan double URL encoding.
     * @see CWE-28 Path Traversal: '%252E%252E%252F' (Double URL Encoded)
     */
    public function testCanAccessSecretFileWithDoubleEncoding()
    {
        $scriptName = 'vuln_double_encoded_traversal.php';

        $cleanTraversalPath = '../secret_dir/secret.txt';
        $expectedValueInGET = str_replace(
            ['../', '/'],
            ['%2e%2e%2f', '%2f'],
            $cleanTraversalPath
        );
        $urlPayload = str_replace('%', '%25', $expectedValueInGET);

        $params = ['file' => $urlPayload];
        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString(htmlspecialchars($this->secretContent), $output, "Gagal via double encoding. Output:\n" . $output);
        
        $expectedBaseDir = realpath($this->baseVulnerableFilesPath . '/safe_dir/') . DIRECTORY_SEPARATOR;
        $this->assertStringContainsString("Base Directory: " . htmlspecialchars($expectedBaseDir), $output, "Base directory salah. Output:\n" . $output);

        $this->assertStringContainsString("Input \$_GET['file'] (expected to be singly decoded by PHP): " . htmlspecialchars($expectedValueInGET), $output, "Input _GET tidak sesuai. Output:\n" . $output);
        $this->assertStringContainsString("After script's urldecode() (expected to be doubly decoded): " . htmlspecialchars($cleanTraversalPath), $output, "Hasil decode kedua tidak sesuai. Output:\n" . $output);
        
        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/secret_dir/secret.txt');
        $this->assertStringContainsString("Resolved real path: " . htmlspecialchars($fullExpectedResolvedPath), $output, "Path yang di-resolve tidak mengandung target yang benar. Output:\n" . $output);
    }
}