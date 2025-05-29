<?php // tests/BasicRelativeTraversalTest.php

namespace Tests;

class BasicRelativeTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * Menguji path traversal dasar untuk mengakses file rahasia.
     * @see CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
     * @see CWE-23 Relative Path Traversal
     */
    public function testCanAccessSecretFileWithRelativeTraversal()
    {
        $scriptName = 'vuln_basic_relative_traversal.php';
        $payload = '../secret_dir/secret.txt';
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString(htmlspecialchars($this->secretContent), $output, "Gagal mengambil konten rahasia. Output:\n" . $output);
        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/secret_dir/secret.txt');
        $this->assertStringContainsString("Resolved real path: " . htmlspecialchars($fullExpectedResolvedPath), $output, "Path yang di-resolve tidak mengandung target yang benar. Output:\n" . $output);
    }

    /**
     * Menguji path traversal untuk mengakses file sistem yang disimulasikan.
     * @see CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')
     * @see CWE-23 Relative Path Traversal
     * @see CWE-34 Path Traversal: '.../...//'
     */
    public function testAttemptsToAccessSimulatedEtcPasswd()
    {
        $scriptName = 'vuln_basic_relative_traversal.php';
        $payload = '../etc/passwd'; // Dari safe_dir, naik satu level, lalu ke etc/passwd
        $params = ['file' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString(htmlspecialchars($this->etcPasswdContent), $output, "Gagal mengambil konten passwd yang disimulasikan. Output:\n" . $output);
        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/etc/passwd');
        $this->assertStringContainsString("Resolved real path: " . htmlspecialchars($fullExpectedResolvedPath), $output, "Path passwd yang di-resolve tidak benar. Output:\n" . $output);
    }
}