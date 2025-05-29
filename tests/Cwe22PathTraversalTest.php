<?php
// tests/Cwe22PathTraversalTest.php
namespace Tests;

class Cwe22PathTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * @dataProvider cwe22PatternsProvider
     */
    public function testPathTraversal(string $description, string $pattern, string $targetFileKey)
    {
        $this->runFileReadTest("CWE-22 Test ($description): $pattern", $pattern, $targetFileKey);
    }

    public function cwe22PatternsProvider(): array
    {
        // Payloads are relative to $sandboxBase in vuln_file_read.php
        // (which is PROJECT_ROOT/vulnerable_files/safe_dir/)
        return [
            // description, pattern, targetFileKey
            ['Access secret.txt (forward slash)', '../secret_dir/secret.txt', 'secret.txt'],
            ['Access secret.txt (backward slash)', '..\\secret_dir\\secret.txt', 'secret.txt'],
        ];
    }
}
?>