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
    protected string $publicModuleContent = '<?php echo "Ini adalah konten modul publik."; ?>';
    protected string $etcPasswdContent = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin";
    protected string $windowsHostsContent = "127.0.0.1 localhost\r\n::1 localhost";

    protected string $baseVulnerableFilesPath;

    public function __construct(?string $name = null, array $data = [], $dataName = '')
    {
        parent::__construct($name, $data, $dataName);
        // Inisialisasi path dasar ke vulnerable_files
        $constructedPath = __DIR__ . '/../vulnerable_files';
        $this->baseVulnerableFilesPath = realpath($constructedPath);

        // Jika path tidak ada, $this->baseVulnerableFilesPath akan false.
        // Ini akan ditangani di setUp() atau setUpBeforeClass().
    }

    /**
     * Menjalankan skrip PHP yang rentan dan menangkap outputnya.
     * @param string $scriptName Nama file skrip di direktori src/.
     * @param array $getParams Parameter GET yang akan dikirim ke skrip.
     * @return string Output dari skrip.
     */
    protected function executeScript(string $scriptName, array $getParams): string
    {
        $originalGet = $_GET;
        $originalServer = $_SERVER;

        $_GET = $getParams;
        // Simulasikan beberapa variabel server minimal yang mungkin dibutuhkan skrip
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['SCRIPT_NAME'] = '/src/' . $scriptName;
        $_SERVER['QUERY_STRING'] = http_build_query($getParams);

        // Path absolut ke skrip yang akan diuji
        $scriptPath = realpath(__DIR__ . '/../src/' . $scriptName);

        if ($scriptPath === false || !file_exists($scriptPath)) {
            $this->fail("Script file not found or path invalid: " . __DIR__ . '/../src/' . $scriptName);
        }

        ob_start();
        include $scriptPath; // Include skrip untuk menjalankannya dalam lingkup ini
        $output = ob_get_clean();

        // Kembalikan variabel global ke keadaan semula
        $_GET = $originalGet;
        $_SERVER = $originalServer;

        return $output;
    }

    /**
     * Dipanggil sekali sebelum tes pertama dalam kelas ini dijalankan.
     */
    public static function setUpBeforeClass(): void
    {
        $basePath = realpath(__DIR__ . '/../vulnerable_files');
        if ($basePath === false || !is_dir($basePath)) {
            // Anda bisa throw exception di sini jika direktori ini krusial dan harus ada
            // throw new \Exception("Direktori vulnerable_files tidak ditemukan. Pastikan sudah disiapkan.");
            // Atau cukup catat peringatan (PHPUnit mungkin tidak menampilkannya kecuali ada kegagalan)
            // fwrite(STDERR, "PERINGATAN: Direktori vulnerable_files tidak ditemukan.\n");
        }
    }

    /**
     * Dipanggil sebelum setiap metode tes dalam kelas ini dijalankan.
     */
    protected function setUp(): void
    {
        if ($this->baseVulnerableFilesPath === false || !is_dir($this->baseVulnerableFilesPath)) {
            $this->markTestSkipped("Direktori vulnerable_files tidak ditemukan atau tidak dapat diakses di '" . __DIR__ . "/../vulnerable_files" . "'. Harap siapkan direktori dan file-file dummy secara manual.");
        }
        // Contoh verifikasi file penting, bisa diperluas
        if (!file_exists($this->baseVulnerableFilesPath . '/secret_dir/secret.txt')) {
             $this->markTestSkipped("File /secret_dir/secret.txt tidak ditemukan di vulnerable_files. Tes mungkin gagal atau diskip.");
        }
         if (!file_exists($this->baseVulnerableFilesPath . '/safe_dir/legit.txt')) {
             $this->markTestSkipped("File /safe_dir/legit.txt tidak ditemukan di vulnerable_files. Tes mungkin gagal atau diskip.");
        }
    }

    /**
     * Dipanggil setelah setiap metode tes dalam kelas ini dijalankan.
     */
    protected function tearDown(): void
    {
        // Tidak ada penghapusan file di sini untuk menjaga file yang disiapkan manual.
        // Jika tes spesifik membuat file sementara, tes tersebut yang harus membersihkannya.
    }
}