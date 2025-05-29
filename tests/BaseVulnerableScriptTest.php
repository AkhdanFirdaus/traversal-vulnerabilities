<?php // tests/BaseVulnerableScriptTest.php

namespace Tests;

use PHPUnit\Framework\TestCase;

abstract class BaseVulnerableScriptTest extends TestCase
{
    // Konten file dummy yang diharapkan ada di ./vulnerable_files/
    protected string $secretContent = "This is the TOP SECRET content!";
    protected string $adminPanelContent = "<h1>Admin Panel</h1>";
    protected string $dbConfigContent = "<?php // DB Config";
    protected string $legitContent = "This is a public file.";
    protected string $publicModuleContent = '<?php echo "Ini adalah konten modul publik."; ?>'; // Konten modul publik
    protected string $etcPasswdContent = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin";
    protected string $windowsHostsContent = "127.0.0.1 localhost\r\n::1 localhost";

    /**
     * Path absolut ke direktori vulnerable_files.
     * Didefinisikan sekali untuk konsistensi.
     */
    protected string $baseVulnerableFilesPath;

    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        // Inisialisasi path dasar di sini atau di setUpBeforeClass jika Anda ingin.
        // Menggunakan realpath untuk mendapatkan path absolut kanonis.
        $this->baseVulnerableFilesPath = realpath(__DIR__ . '/../vulnerable_files');
        if ($this->baseVulnerableFilesPath === false) {
            // Jika vulnerable_files tidak ada sama sekali, ini masalah besar.
            // Mungkin lebih baik throw exception atau fail di sini.
            // Untuk sekarang, kita biarkan dan tes mungkin gagal jika file tidak ditemukan.
            // Atau, Anda bisa memutuskan untuk membuatnya jika tidak ada:
            // if (!mkdir(__DIR__ . '/../vulnerable_files', 0777, true) && !is_dir(__DIR__ . '/../vulnerable_files')) {
            //      throw new \RuntimeException(sprintf('Directory "%s" was not created', __DIR__ . '/../vulnerable_files'));
            // }
            // $this->baseVulnerableFilesPath = realpath(__DIR__ . '/../vulnerable_files');
            // Namun, karena Anda bilang sudah menyiapkan, kita asumsikan ada.
        }
    }

    protected function executeScript(string $scriptName, array $getParams): string
    {
        $originalGet = $_GET;
        $originalServer = $_SERVER;

        $_GET = $getParams;
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['SCRIPT_NAME'] = '/src/' . $scriptName;

        $scriptPath = __DIR__ . '/../src/' . $scriptName;

        if (!file_exists($scriptPath)) {
            $this->fail("Script file not found: {$scriptPath}");
        }

        ob_start();
        include $scriptPath;
        $output = ob_get_clean();

        $_GET = $originalGet;
        $_SERVER = $originalServer;

        return $output;
    }

    /**
     * Dipanggil sekali sebelum tes pertama dalam kelas ini dijalankan.
     * Anda bisa gunakan ini untuk setup yang lebih global jika diperlukan.
     */
    public static function setUpBeforeClass(): void
    {
        // Jika Anda perlu melakukan sesuatu sekali per kelas tes, lakukan di sini.
        // Contoh: Memastikan direktori vulnerable_files utama ada.
        $basePath = realpath(__DIR__ . '/../vulnerable_files');
        if ($basePath === false || !is_dir($basePath)) {
            // Ini akan menghentikan eksekusi tes jika direktori utama tidak ada.
            // Anda mungkin ingin menangani ini dengan cara berbeda.
            // throw new \Exception("Direktori vulnerable_files tidak ditemukan. Pastikan sudah disiapkan.");
            echo "PERINGATAN: Direktori vulnerable_files tidak ditemukan di " . realpath(__DIR__ . '/..') . "/vulnerable_files. Tes mungkin gagal.\n";
        }
    }


    /**
     * Metode setUp() sekarang tidak akan membuat file, hanya bisa digunakan
     * untuk setup per-tes jika ada.
     * Kita asumsikan file-file di vulnerable_files sudah disiapkan secara manual.
     */
    protected function setUp(): void
    {
        // Pastikan direktori vulnerable_files utama dapat diakses
        if ($this->baseVulnerableFilesPath === false || !is_dir($this->baseVulnerableFilesPath)) {
            $this->markTestSkipped("Direktori vulnerable_files tidak ditemukan atau tidak dapat diakses di '{$this->baseVulnerableFilesPath}'. Harap siapkan secara manual.");
        }
        // Tidak ada lagi pembuatan file di sini agar tidak menimpa file manual Anda.
        // Anda bisa menambahkan verifikasi di sini bahwa file-file yang dibutuhkan oleh tes *memang ada*,
        // dan skip tes jika tidak ada. Contoh:
        // if (!file_exists($this->baseVulnerableFilesPath . '/secret_dir/secret.txt')) {
        //     $this->markTestSkipped("File secret_files/secret.txt tidak ditemukan di vulnerable_files.");
        // }
    }

    /**
     * Metode tearDown() sekarang TIDAK akan menghapus file atau direktori
     * dari vulnerable_files.
     */
    protected function tearDown(): void
    {
        // Tidak ada lagi penghapusan file di sini.
        // Jika ada file sementara yang DIBUAT OLEH TES SPESIFIK (bukan bagian dari setup manual Anda),
        // maka file sementara itu yang seharusnya dibersihkan di sini atau di tearDown tes spesifik tersebut.
    }

    // Helper ini mungkin tidak lagi dibutuhkan jika setUp tidak membuat direktori.
    // private function ensureDirectoryExists(string $path): void
    // {
    //     if (!is_dir($path)) {
    //         if (!mkdir($path, 0777, true) && !is_dir($path)) {
    //             throw new \RuntimeException(sprintf('Directory "%s" was not created', $path));
    //         }
    //     }
    // }
}