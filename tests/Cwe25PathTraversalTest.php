<?php
// tests/Cwe25PathTraversalTest.php
namespace Tests;

class Cwe25PathTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * @dataProvider cwe25AbsolutePathTargetProvider
     */
    public function testAbsolutePathTraversal(string $relativeVulnerableFilePathToTarget, string $targetFileKeyForAssertion)
    {
        // $this->projectRoot is available here (e.g. /app)
        // The payload for the vulnerable script will be an "absolute" path to a file within vulnerable_files
        $absolutePayload = $this->projectRoot . '/vulnerable_files/' . $relativeVulnerableFilePathToTarget;
        $this->runFileReadTest("CWE-25 Absolute Path to: $relativeVulnerableFilePathToTarget", $absolutePayload, $targetFileKeyForAssertion);
    }

    public function cwe25AbsolutePathTargetProvider(): array
    {
        // Provide paths relative to the project_root/vulnerable_files/
        // The targetFileKeyForAssertion is also relative to project_root/vulnerable_files for getTargetFileContent()
        return [
            // relative path in vulnerable_files to target, targetFileKey for getTargetFileContent
            ['etc/passwd', 'etc/passwd'],
            ['Windows/System32/drivers/etc/hosts', 'windows/hosts'],
        ];
    }
}
?>