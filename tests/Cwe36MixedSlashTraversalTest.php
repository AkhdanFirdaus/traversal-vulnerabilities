<?php

namespace Tests;

class Cwe36MixedSlashTraversalTest extends BaseVulnerableScript
{
    public function testMixedSlashes(): void
    {
        $result = $this->reader->read('../..\\../vulnerable_files/secret_dir/secret.txt');
        $this->assertStringNotContainsString('TOP SECRET', $result);
    }
}
