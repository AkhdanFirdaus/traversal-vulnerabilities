<?php // tests/ObfuscatedMixedSlashesTraversalTest.php

namespace Tests;

class ObfuscatedMixedSlashesTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * Menguji path traversal menggunakan teknik obfuskasi.
     * @see CWE-26 Path Traversal: '.../...//'
     * @see CWE-40 Path Traversal: '....//'
     * @see CWE-41 Path Traversal: '....\'
     */
    public function testObfuscatedTraversalToSecretFile()
    {
        $scriptName = 'vuln_obfuscated_mixed_slashes_traversal.php';
        $payloads = [
            // Dari safe_dir, targetnya adalah ../secret_dir/secret.txt
            '..././../secret_dir/secret.txt',      // Tiga titik, dot-slash
            '....//....//../secret_dir/secret.txt', // Empat titik, double slash
            '././../secret_dir/./secret.txt'      // Banyak dot-slash
        ];
        
        $success = false;
        $lastOutput = '';
        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/secret_dir/secret.txt');

        foreach ($payloads as $payload) {
            $params = ['file' => $payload];
            $output = $this->executeScript($scriptName, $params);
            $lastOutput = "Payload: $payload\nOutput:\n$output";
            if (str_contains($output, htmlspecialchars($this->secretContent)) &&
                str_contains($output, "Resolved real path: " . htmlspecialchars($fullExpectedResolvedPath))) {
                $success = true;
                break;
            }
        }
        $this->assertTrue($success, "Gagal via obfuscated dengan semua variasi payload. Output terakhir:\n" . $lastOutput);
    }

    /**
     * Menguji path traversal menggunakan kombinasi slash (forward dan backward).
     * @see CWE-36 Path Traversal: '\../filedir' (Mixed Slashes)
     */
    public function testMixedSlashesTraversalToSecretFile()
    {
        $scriptName = 'vuln_obfuscated_mixed_slashes_traversal.php';
        $payloadMixed = '../secret_dir/secret.txt'; // Kombinasi \ dan /

        $params = ['file' => $payloadMixed];
        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString(htmlspecialchars($this->secretContent), $output, "Gagal via mixed slashes. Output:\n" . $output);
        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/secret_dir/secret.txt');
        $this->assertStringContainsString("Resolved real path: " . htmlspecialchars($fullExpectedResolvedPath), $output, "Path mixed slashes yang di-resolve salah. Output:\n" . $output);
    }
}
