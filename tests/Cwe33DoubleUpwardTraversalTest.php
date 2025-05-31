<?php

namespace Tests;

class Cwe33DoubleUpwardTraversalTest extends BaseVulnerableScript
{
    public function testNestedUpTraversal(): void
    {
        $result = $this->reader->read('folder/sub/../../secret_dir/secret.txt');
        $this->assertStringNotContainsString('TOP SECRET', $result);
    }
}
