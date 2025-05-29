<?php // tests/AbsolutePathTraversalTest.php

namespace Tests;

class AbsolutePathTraversalTest extends BaseVulnerableScriptTest
{
    public function testAccessesSimulatedEtcPasswdWithAbsoluteUnixPath()
    {
        $scriptName = 'vuln_absolute_path_traversal.php';
        // Skrip akan memetakan '/etc/passwd' ke 'vulnerable_files/etc/passwd'
        $params = ['path' => '/etc/passwd'];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->etcPasswdContent, $output, "Gagal mengambil konten /etc/passwd yang disimulasikan melalui path absolut Unix.");
        $expectedResolvedPathFragment = DIRECTORY_SEPARATOR . 'vulnerable_files' . DIRECTORY_SEPARATOR . 'etc' . DIRECTORY_SEPARATOR . 'passwd';
        // Cek apakah output mengandung path yang di-resolve dengan benar oleh skrip
        $this->assertStringContainsString($expectedResolvedPathFragment, $output, "Path absolut Unix yang di-resolve tidak benar.");
    }

    public function testAccessesSimulatedWindowsHostsWithAbsoluteWindowsPath()
    {
        $scriptName = 'vuln_absolute_path_traversal.php';
        // Skrip akan memetakan 'C:\Windows\System32\drivers\etc\hosts' ke 'vulnerable_files/Windows/System32/drivers/etc/hosts'
        $params = ['path' => 'C:\\Windows\\System32\\drivers\\etc\\hosts'];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->windowsHostsContent, $output, "Gagal mengambil konten host Windows yang disimulasikan melalui path absolut Windows.");
        $expectedResolvedPathFragment = DIRECTORY_SEPARATOR . 'vulnerable_files' . DIRECTORY_SEPARATOR . 'Windows' . DIRECTORY_SEPARATOR . 'System32' . DIRECTORY_SEPARATOR . 'drivers' . DIRECTORY_SEPARATOR . 'etc' . DIRECTORY_SEPARATOR . 'hosts';
        $this->assertStringContainsString($expectedResolvedPathFragment, $output, "Path absolut Windows yang di-resolve tidak benar.");
    }

    public function testAccessesLegitFileWithRelativePath()
    {
        $scriptName = 'vuln_absolute_path_traversal.php';
        // Skrip akan menggunakan $scriptSafeBaseDir untuk path relatif
        // $scriptSafeBaseDir adalah vulnerable_files/safe_dir/
        $params = ['path' => 'legit.txt'];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString($this->legitContent, $output);
        $expectedResolvedPathFragment = DIRECTORY_SEPARATOR . 'vulnerable_files' . DIRECTORY_SEPARATOR . 'safe_dir' . DIRECTORY_SEPARATOR . 'legit.txt';
        $this->assertStringContainsString($expectedResolvedPathFragment, $output);
    }
}