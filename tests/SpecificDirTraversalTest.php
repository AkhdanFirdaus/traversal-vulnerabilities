<?php // tests/SpecificDirTraversalTest.php

namespace Tests;

class SpecificDirTraversalTest extends BaseVulnerableScriptTest
{
    public function testCanAccessAdminPanelViaSpecificDirTraversal()
    {
        $scriptName = 'vuln_specific_dir_traversal.php';
        // $modulesBaseDir skrip adalah .../safe_dir/modules/
        // Payload '../../secret_dir/admin/panel.php' akan menjadi:
        // .../safe_dir/modules/../../secret_dir/admin/panel.php
        // Ini akan resolve ke .../vulnerable_files/secret_dir/admin/panel.php
        $params = ['module' => '../../secret_dir/admin/panel.php'];

        $output = $this->executeScript($scriptName, $params);

        $this->assertStringContainsString($this->adminPanelContent, $output, "Gagal mengambil konten panel admin.");
        // Cek path yang dicoba oleh skrip (mungkin perlu disesuaikan berdasarkan output aktual skrip)
        $this->assertStringContainsString('modules' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'secret_dir' . DIRECTORY_SEPARATOR . 'admin' . DIRECTORY_SEPARATOR . 'panel.php', $output);
    }

    public function testCanAccessDbConfigViaSpecificDirTraversal()
    {
        $scriptName = 'vuln_specific_dir_traversal.php';
        $params = ['module' => '../../secret_dir/config/db.php'];

        $output = $this->executeScript($scriptName, $params);
        // dbConfigContent adalah "<?php // DB Config", perlu htmlspecialchars karena outputnya text/plain
        // Jika skrip Anda melakukan htmlspecialchars, maka tidak perlu di sini.
        // Asumsi skrip include langsung, maka outputnya akan apa adanya.
        $this->assertStringContainsString($this->dbConfigContent, $output, "Gagal mengambil konten konfigurasi DB.");
        $this->assertStringContainsString('modules' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'secret_dir' . DIRECTORY_SEPARATOR . 'config' . DIRECTORY_SEPARATOR . 'db.php', $output);
    }
}