<?php

namespace Tests;

class Cwe31MidPathTraversalTest extends BaseVulnerableScript
{
    public function testMiddlePathTraversal(): void
    {
        $result = $this->reader->read('safe_dir/../../secret_dir/secret.txt');
        $this->assertStringNotContainsString('TOP SECRET', $result);
    }
}
