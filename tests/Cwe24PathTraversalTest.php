<?php // tests/Cwe24PathTraversalTest.php
namespace Tests;

class Cwe24PathTraversalTest extends BaseVulnerableScriptTest
{
    /**
     * @dataProvider cwe24PatternsProvider
     */
    public function testPathTraversal(string $description, string $pattern, string $targetFileKey)
    {
        $this->runFileReadTest("CWE-24 Test ($description): $pattern", $pattern, $targetFileKey);
    }

    public function cwe24PatternsProvider(): array
    {
        return [
            ['Traversal to Specific Directory (admin panel content)', '../secret_dir/admin/panel.php', 'admin_panel_content_as_text'],
            // Add other CWE-24 patterns from patterns.json if necessary, e.g., for "../config"
            // For example, if you had "../config" and wanted to read "db.php"
            // ['Traversal to config/db.php', '../secret_dir/config/db.php', 'config_db_content_as_text'],
            // You'd need to add 'config_db_content_as_text' case to runFileReadTest in BaseVulnerableScriptTest
        ];
    }
}
?>