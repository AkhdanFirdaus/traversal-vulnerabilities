<?php // tests/AbsolutePathTraversalTest.php

namespace Tests;

class AbsolutePathTraversalTest extends BaseVulnerableScriptTest
{
    public function testAccessesSimulatedEtcPasswdWithAbsoluteUnixPath()
    {
        $scriptName = 'vuln_absolute_path_traversal.php';
        $payload = '/etc/passwd'; // Akan dipetakan ke vulnerable_files/etc/passwd
        $params = ['path' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->etcPasswdContent, $output, "Gagal mengambil passwd. Output:\n" . $output);
        $expectedPathEnd = 'vulnerable_files' . DIRECTORY_SEPARATOR . 'etc' . DIRECTORY_SEPARATOR . 'passwd';
        $this->assertStringContainsString($expectedPathEnd, $output);
    }

    public function testAccessesSimulatedWindowsHostsWithAbsoluteWindowsPath()
    {
        $scriptName = 'vuln_absolute_path_traversal.php';
        $payload = '\\Windows\\System32\\drivers\\etc\\hosts'; // Akan dipetakan
        $params = ['path' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->windowsHostsContent, $output, "Gagal mengambil hosts Windows. Output:\n" . $output);
        $expectedPathEnd = 'vulnerable_files' . DIRECTORY_SEPARATOR . 'Windows' . DIRECTORY_SEPARATOR . 'System32' . DIRECTORY_SEPARATOR . 'drivers' . DIRECTORY_SEPARATOR . 'etc' . DIRECTORY_SEPARATOR . 'hosts';
        $this->assertStringContainsString($expectedPathEnd, $output);
    }

    public function testAccessesLegitFileWithRelativePathUsingAbsoluteScript()
    {
        $scriptName = 'vuln_absolute_path_traversal.php';
        // Path relatif akan menggunakan $scriptSafeBaseDir dari skrip
        $payload = '/safe_dir/legit.txt';
        $params = ['path' => $payload];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString($this->legitContent, $output, "Gagal mengambil legit.txt. Output:\n" . $output);
        $expectedPathEnd = 'vulnerable_files' . DIRECTORY_SEPARATOR . 'safe_dir' . DIRECTORY_SEPARATOR . 'legit.txt';
        $this->assertStringContainsString($expectedPathEnd, $output);
    }
}