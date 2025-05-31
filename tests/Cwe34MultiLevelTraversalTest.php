<?php

namespace Tests;

class Cwe34MultiLevelTraversalTest extends BaseVulnerableScript
{
    public function testThreeLevelTraversal(): void
    {
        $result = $this->reader->read('../../../etc/passwd');
        $this->assertStringNotContainsString('root', $result);
    }
}
