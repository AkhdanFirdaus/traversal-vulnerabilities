<?php
// tests/Cwe36PathTraversalTest.php
namespace Tests;


class Cwe36PathTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * @dataProvider cwe36PatternsProvider
     */
    public function testPathTraversal(string $description, string $pattern, string $targetFileKey)
    {
        $this->runFileReadTest("CWE-36 Test ($description): $pattern", $pattern, $targetFileKey);
    }

    public function cwe36PatternsProvider(): array
    {
        // Payloads from original genericTraversalPatternsProvider for CWE-36
        // Example: ['Mixed Slashes', '..\\/../secret_dir\\secret.txt', 'secret.txt']
        // This pattern is relative to $sandboxBase in vuln_file_read.php
        return [
            ['Mixed Slashes to secret.txt', '..\\/../secret_dir\\secret.txt', 'secret.txt'],
            // Add other CWE-36 specific patterns from patterns.json if available and distinct
            // Example from patterns.json: "..\\/..\\/windows\\system32"
            // This would target PROJECT_ROOT/vulnerable_files/Windows/System32/drivers/etc/hosts
            // (assuming 'windows\\system32' is part of path to hosts file for testing)
            // If it tries to access an actual system dir, the payload would be different.
            // For our controlled environment:
            ['Mixed Slashes to Windows hosts', '../..\\Windows/System32/drivers/etc\\hosts', 'windows/hosts'],
        ];
    }
}
?>