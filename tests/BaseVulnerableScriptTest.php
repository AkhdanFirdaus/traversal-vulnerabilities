<?php
// tests/BaseVulnerableScriptTest.php
namespace Tests;

use PHPUnit\Framework\TestCase;

abstract class BaseVulnerableScriptTest extends TestCase
{
    protected string $projectRoot;
    protected array $allPatternsData; // Kept if individual tests still want to reference it, though providers are now specific

    // Constants for the script primarily targeted by these path traversal tests
    protected const SCRIPT_NAME_FILE_READ = 'vuln_file_read.php';
    protected const PARAM_NAME_FILE_READ = 'file';

    protected function setUp(): void
    {
        $this->projectRoot = realpath(__DIR__ . '/..');
        if (!$this->projectRoot) {
            throw new \RuntimeException("Project root could not be determined. __DIR__ is " . __DIR__);
        }

        $patternsJsonPath = $this->projectRoot . '/patterns.json';
        if (!file_exists($patternsJsonPath)) {
            throw new \RuntimeException("patterns.json not found at: " . $patternsJsonPath);
        }
        $patternsJson = file_get_contents($patternsJsonPath);
        $this->allPatternsData = json_decode($patternsJson, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new \RuntimeException("Error decoding patterns.json: " . json_last_error_msg());
        }
    }

    protected function executeVulnerableScript(string $scriptName, string $paramName, string $payload): string
    {
        $originalGet = $_GET;
        $_GET = [];
        $_GET[$paramName] = $payload;

        ob_start();
        try {
            $scriptPath = $this->projectRoot . '/src/' . $scriptName;
            if (!file_exists($scriptPath)) {
                throw new \RuntimeException("Script not found: {$scriptPath}");
            }
            include $scriptPath;
        } finally {
            $output = ob_get_clean();
            $_GET = $originalGet;
        }
        return $output;
    }

    protected function getTargetFileContent(string $relativePathToFile): string
    {
        // $relativePathToFile is relative to vulnerable_files/ in the project root
        $fullPath = $this->projectRoot . '/vulnerable_files/' . $relativePathToFile;
        if (!file_exists($fullPath) || !is_readable($fullPath)) {
            trigger_error("Test assertion error: Cannot read target file: {$fullPath}", E_USER_WARNING);
            return "Error reading expected content: " . $relativePathToFile;
        }
        return file_get_contents($fullPath);
    }

    protected function getSecretTextContent(): string
    {
        return $this->getTargetFileContent('secret_dir/secret.txt');
    }

    protected function getEtcPasswdContent(): string
    {
        return $this->getTargetFileContent('etc/passwd');
    }

    protected function getWindowsHostsContent(): string
    {
        return $this->getTargetFileContent('Windows/System32/drivers/etc/hosts');
    }

    protected function runFileReadTest(string $message, string $payload, string $targetFileKey)
    {
        // Using constants defined in this base class, assuming all these CWE tests target the same script/param
        $output = $this->executeVulnerableScript(static::SCRIPT_NAME_FILE_READ, static::PARAM_NAME_FILE_READ, $payload);
        $expectedContent = '';

        switch ($targetFileKey) {
            case 'secret.txt':
                $expectedContent = $this->getSecretTextContent();
                break;
            case 'etc/passwd':
                $expectedContent = $this->getEtcPasswdContent();
                break;
            case 'windows/hosts':
                $expectedContent = $this->getWindowsHostsContent();
                break;
            case 'admin_panel_content_as_text':
                $expectedContent = $this->getTargetFileContent('secret_dir/admin/panel.php');
                break;
            case 'config_db_content_as_text':
                $expectedContent = $this->getTargetFileContent('secret_dir/config/db.php');
                break;
            case 'safe_dir/legit.txt':
                 $expectedContent = $this->getTargetFileContent('safe_dir/legit.txt');
                 break;
            default:
                $this->fail("Unknown targetFileKey in runFileReadTest: '$targetFileKey' for test message: $message");
        }
        $this->assertEquals($expectedContent, $output, "Test Failed: $message. Payload: $payload");
    }
}
?>