<?php // tests/SpecificDirTraversalTest.php

namespace Tests;

class SpecificDirTraversalTest extends BaseVulnerableScriptTest
{
    public function testCanLoadPublicModuleSafely()
    {
        $scriptName = 'vuln_specific_dir_traversal.php';
        $params = ['module_name' => 'public_module.php']; // Modul sah

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString(htmlspecialchars($this->publicModuleContent), $output, "Gagal memuat modul publik. Output:\n" . $output);
        $expectedPathEnd = 'safe_dir' . DIRECTORY_SEPARATOR . 'modules' . DIRECTORY_SEPARATOR . 'public_module.php';
        $this->assertStringContainsString($expectedPathEnd, $output);
    }

    public function testCanAccessAdminPanelViaSpecificDirTraversal()
    {
        $scriptName = 'vuln_specific_dir_traversal.php';
        // Payload untuk keluar dari 'vulnerable_files/safe_dir/modules/'
        // ke 'vulnerable_files/secret_dir/admin/panel.php'
        $payload = '../../secret_dir/admin/panel.php';
        $params = ['module_name' => $payload];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString(htmlspecialchars($this->adminPanelContent), $output, "Gagal mengambil konten panel admin. Output:\n" . $output);
        $expectedPathEnd = 'secret_dir' . DIRECTORY_SEPARATOR . 'admin' . DIRECTORY_SEPARATOR . 'panel.php';
        $this->assertStringContainsString($expectedPathEnd, $output);
    }

    public function testCanAccessDbConfigViaSpecificDirTraversal()
    {
        $scriptName = 'vuln_specific_dir_traversal.php';
        $payload = '../../secret_dir/config/db.php';
        $params = ['module_name' => $payload];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString(htmlspecialchars($this->dbConfigContent), $output, "Gagal mengambil konten config DB. Output:\n" . $output);
        $expectedPathEnd = 'secret_dir' . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'db.php';
        $this->assertStringContainsString($expectedPathEnd, $output);
    }
}