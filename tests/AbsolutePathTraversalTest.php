<?php // tests/AbsolutePathTraversalTest.php

namespace Tests;

class AbsolutePathTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * Menguji akses ke file passwd yang disimulasikan menggunakan path absolut Unix.
     * @see CWE-25 Path Traversal: '/../filedir' (Absolute Path)
     * @see CWE-36 Path Traversal: Absolute
     */
    public function testAccessesSimulatedEtcPasswdWithAbsoluteUnixPath()
    {
        $scriptName = 'vuln_absolute_path_traversal.php';
        $payload = '/etc/passwd'; // Akan dipetakan ke vulnerable_files/etc/passwd
        $params = ['path' => $payload];
        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString(htmlspecialchars($this->etcPasswdContent), $output, "Gagal mengambil passwd. Output:\n" . $output);
        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/etc/passwd');
        $this->assertStringContainsString("Resolved real path (final attempt): " . htmlspecialchars($fullExpectedResolvedPath), $output);
        $this->assertStringContainsString("Input appears to be an absolute path (simulated access).", $output);
    }

    /**
     * Menguji akses ke file hosts Windows yang disimulasikan menggunakan path absolut Windows.
     * @see CWE-25 Path Traversal: '/../filedir' (Absolute Path)
     * @see CWE-36 Path Traversal: Absolute
     */
    public function testAccessesSimulatedWindowsHostsWithAbsoluteWindowsPath()
    {
        $scriptName = 'vuln_absolute_path_traversal.php';
        $payload = 'C:\\Windows\\System32\\drivers\\etc\\hosts'; // Menyertakan drive letter
        $params = ['path' => $payload];
        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString(htmlspecialchars($this->windowsHostsContent), $output, "Gagal mengambil hosts Windows. Output:\n" . $output);
        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/Windows/System32/drivers/etc/hosts');
        $this->assertStringContainsString("Resolved real path (final attempt): " . htmlspecialchars($fullExpectedResolvedPath), $output);
        $this->assertStringContainsString("Input appears to be an absolute path (simulated access).", $output);
    }

    /**
     * Menguji akses ke file legit menggunakan path relatif melalui skrip yang juga menangani path absolut.
     */
    public function testAccessesLegitFileWithRelativePathUsingAbsoluteScript()
    {
        $scriptName = 'vuln_absolute_path_traversal.php';
        $payloadRelative = 'legit.txt'; // Path relatif dari safe_dir
        $paramsRelative = ['path' => $payloadRelative];

        $outputRelative = $this->executeScript($scriptName, $paramsRelative);
        $this->assertStringContainsString(htmlspecialchars($this->legitContent), $outputRelative, "Gagal mengambil legit.txt via path RELATIF. Output:\n" . $outputRelative);
        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/safe_dir/legit.txt');
        $this->assertStringContainsString("Resolved real path (final attempt): " . htmlspecialchars($fullExpectedResolvedPath), $outputRelative);
        $this->assertStringContainsString("Input appears to be a relative path.", $outputRelative);
    }
}
