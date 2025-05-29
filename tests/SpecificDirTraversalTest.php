<?php // tests/SpecificDirTraversalTest.php

namespace Tests;

class SpecificDirTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * Memastikan modul publik yang sah dapat dimuat.
     */
    public function testCanLoadPublicModuleSafely()
    {
        $scriptName = 'vuln_specific_dir_traversal.php';
        $params = ['module_name' => 'public_module.php'];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString(htmlspecialchars($this->publicModuleContent), $output, "Gagal memuat modul publik. Output:\n" . $output);
        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/safe_dir/modules/public_module.php');
        $this->assertStringContainsString("Resolved real path: " . htmlspecialchars($fullExpectedResolvedPath), $output);
    }

    /**
     * Menguji traversal untuk mengakses panel admin.
     * @see CWE-24 Path Traversal: '../filedir'
     */
    public function testCanAccessAdminPanelViaSpecificDirTraversal()
    {
        $scriptName = 'vuln_specific_dir_traversal.php';
        // Dari .../safe_dir/modules/, payload ini akan naik ke .../vulnerable_files/ lalu ke secret_dir
        $payload = '../../secret_dir/admin/panel.php';
        $params = ['module_name' => $payload];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString(htmlspecialchars($this->adminPanelContent), $output, "Gagal mengambil konten panel admin. Output:\n" . $output);
        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/secret_dir/admin/panel.php');
        $this->assertStringContainsString("Resolved real path: " . htmlspecialchars($fullExpectedResolvedPath), $output);
    }

    /**
     * Menguji traversal untuk mengakses konfigurasi DB.
     * @see CWE-24 Path Traversal: '../filedir'
     */
    public function testCanAccessDbConfigViaSpecificDirTraversal()
    {
        $scriptName = 'vuln_specific_dir_traversal.php';
        $payload = '../../secret_dir/config/db.php';
        $params = ['module_name' => $payload];

        $output = $this->executeScript($scriptName, $params);
        $this->assertStringContainsString(htmlspecialchars($this->dbConfigContent), $output, "Gagal mengambil konten config DB. Output:\n" . $output);
        $fullExpectedResolvedPath = realpath($this->baseVulnerableFilesPath . '/secret_dir/config/db.php');
        $this->assertStringContainsString("Resolved real path: " . htmlspecialchars($fullExpectedResolvedPath), $output);
    }
}