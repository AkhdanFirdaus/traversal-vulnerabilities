<?php // tests/BaseVulnerableScriptTest.php

namespace Tests; // Namespace diperbarui

use PHPUnit\Framework\TestCase;

abstract class BaseVulnerableScriptTest extends TestCase
{
    // Konten file dummy yang diharapkan ada di ./vulnerable_files/
    protected string $secretContent = "This is the TOP SECRET content!";
    protected string $adminPanelContent = "<h1>Admin Panel</h1>";
    protected string $dbConfigContent = "<?php // DB Config";
    protected string $legitContent = "This is a public file.";
    protected string $etcPasswdContent = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"; // Konten mock
    protected string $windowsHostsContent = "127.0.0.1 localhost\r\n::1 localhost"; // Konten mock

    protected function executeScript(string $scriptName, array $getParams): string
    {
        $originalGet = $_GET;
        $originalServer = $_SERVER;

        $_GET = $getParams;
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['SCRIPT_NAME'] = '/src/' . $scriptName; // Path skrip relatif terhadap web root (disimulasikan)

        // Path ke skrip yang rentan di direktori src/
        $scriptPath = __DIR__ . '/../src/' . $scriptName; // Diperbarui

        if (!file_exists($scriptPath)) {
            $this->fail("Script file not found: {$scriptPath}");
        }

        ob_start();
        include $scriptPath; // Skrip di src/ akan menggunakan __DIR__ untuk path relatif ke vulnerable_files
        $output = ob_get_clean();

        $_GET = $originalGet;
        $_SERVER = $originalServer;

        return $output;
    }

    protected function setUp(): void
    {
        // Path dasar ke direktori vulnerable_files relatif terhadap direktori tests
        $baseVulnerableFilesPath = realpath(__DIR__ . '/../vulnerable_files');
        if (!$baseVulnerableFilesPath) {
            // Baris berikut akan membuat direktori vulnerable_files jika belum ada.
            // Penting: pastikan direktori project root dapat ditulisi oleh proses PHP.
            if (!mkdir(__DIR__ . '/../vulnerable_files', 0777, true) && !is_dir(__DIR__ . '/../vulnerable_files')) {
                 throw new \RuntimeException(sprintf('Directory "%s" was not created', __DIR__ . '/../vulnerable_files'));
            }
            $baseVulnerableFilesPath = realpath(__DIR__ . '/../vulnerable_files');
        }


        $this->ensureDirectoryExists($baseVulnerableFilesPath . '/safe_dir');
        file_put_contents($baseVulnerableFilesPath . '/safe_dir/legit.txt', $this->legitContent);
        $this->ensureDirectoryExists($baseVulnerableFilesPath . '/safe_dir/modules'); // Ditambahkan untuk SpecificDirTraversalTest

        $this->ensureDirectoryExists($baseVulnerableFilesPath . '/secret_dir');
        file_put_contents($baseVulnerableFilesPath . '/secret_dir/secret.txt', $this->secretContent);

        $this->ensureDirectoryExists($baseVulnerableFilesPath . '/secret_dir/admin');
        file_put_contents($baseVulnerableFilesPath . '/secret_dir/admin/panel.php', $this->adminPanelContent);

        $this->ensureDirectoryExists($baseVulnerableFilesPath . '/secret_dir/config');
        file_put_contents($baseVulnerableFilesPath . '/secret_dir/config/db.php', $this->dbConfigContent);

        $this->ensureDirectoryExists($baseVulnerableFilesPath . '/etc');
        file_put_contents($baseVulnerableFilesPath . '/etc/passwd', $this->etcPasswdContent);

        $this->ensureDirectoryExists($baseVulnerableFilesPath . '/Windows/System32/drivers/etc');
        file_put_contents($baseVulnerableFilesPath . '/Windows/System32/drivers/etc/hosts', $this->windowsHostsContent);
    }

    protected function tearDown(): void
    {
        $baseVulnerableFilesPath = realpath(__DIR__ . '/../vulnerable_files');
        if (!$baseVulnerableFilesPath) return; // Jika direktori tidak ada, tidak ada yang perlu dibersihkan

        @unlink($baseVulnerableFilesPath . '/safe_dir/legit.txt');
        @rmdir($baseVulnerableFilesPath . '/safe_dir/modules'); // Ditambahkan
        @rmdir($baseVulnerableFilesPath . '/safe_dir');

        @unlink($baseVulnerableFilesPath . '/secret_dir/admin/panel.php');
        @rmdir($baseVulnerableFilesPath . '/secret_dir/admin');
        @unlink($baseVulnerableFilesPath . '/secret_dir/config/db.php');
        @rmdir($baseVulnerableFilesPath . '/secret_dir/config');
        @unlink($baseVulnerableFilesPath . '/secret_dir/secret.txt');
        @rmdir($baseVulnerableFilesPath . '/secret_dir');

        @unlink($baseVulnerableFilesPath . '/etc/passwd');
        @rmdir($baseVulnerableFilesPath . '/etc');

        @unlink($baseVulnerableFilesPath . '/Windows/System32/drivers/etc/hosts');
        @rmdir($baseVulnerableFilesPath . '/Windows/System32/drivers/etc');
        @rmdir($baseVulnerableFilesPath . '/Windows/System32/drivers');
        @rmdir($baseVulnerableFilesPath . '/Windows/System32');
        @rmdir($baseVulnerableFilesPath . '/Windows');

        // Hati-hati jika direktori vulnerable_files mungkin digunakan oleh proses lain.
        // Untuk pembersihan total, Anda bisa mempertimbangkan menghapus vulnerable_files jika kosong.
        // if (is_dir($baseVulnerableFilesPath) && count(scandir($baseVulnerableFilesPath)) == 2) { // . and ..
        //     @rmdir($baseVulnerableFilesPath);
        // }
    }

    private function ensureDirectoryExists(string $path): void
    {
        if (!is_dir($path)) {
            if (!mkdir($path, 0777, true) && !is_dir($path)) {
                throw new \RuntimeException(sprintf('Directory "%s" was not created', $path));
            }
        }
    }
}