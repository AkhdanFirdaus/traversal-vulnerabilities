<?php
// tests/BasicFunctionalityTest.php
namespace Tests;

class BasicFunctionalityTest extends BaseVulnerableScriptTest
{
    public function testLegitimateFileAccessInSafeDir()
    {
        $payload = 'legit.txt'; // Relative to $sandboxBase in vuln_file_read.php
        // targetFileKey for runFileReadTest needs to match a case in its switch statement
        $this->runFileReadTest(
            "Legitimate file access (safe_dir/legit.txt)",
            $payload,
            'safe_dir/legit.txt' // This key will be used by getTargetFileContent
        );
    }
}
?>