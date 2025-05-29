<?php
// tests/Cwe23PathTraversalTest.php
namespace Tests;

class Cwe23PathTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * @dataProvider cwe23PatternsProvider
     */
    public function testPathTraversal(string $description, string $pattern, string $targetFileKey)
    {
        $this->runFileReadTest("CWE-23 Test ($description): $pattern", $pattern, $targetFileKey);
    }

    public function cwe23PatternsProvider(): array
    {
        return [
            ['Access etc/passwd (relative)', '../../etc/passwd', 'etc/passwd'],
            ['Access etc/passwd (relative, backslash)', '..\\..\\etc\\passwd', 'etc/passwd'],
            ['Access etc/passwd (relative, mixed)', '../..\\etc/passwd', 'etc/passwd'],
        ];
    }
}
?>