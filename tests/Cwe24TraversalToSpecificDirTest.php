<?php

namespace Tests;

class Cwe24TraversalToSpecificDirTest extends BaseVulnerableScript
{
    public function testAccessAdmin(): void
    {
        $result = $this->reader->read('../secret_dir/admin/panel.php');
        $this->assertStringStartsNotWith('<?php', $result);
    }

    public function testAccessConfig(): void
    {
        $result = $this->reader->read('../secret_dir/config/db.php');
        $this->assertStringNotContainsString('define(', $result);
    }
}
