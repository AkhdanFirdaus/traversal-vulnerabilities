<?php

namespace Tests;

class Cwe32NormalizationTraversalTest extends BaseVulnerableScript
{
    public function testNormalizedTraversal(): void
    {
        $result = $this->reader->read('safe_dir/modules/../legit.txt');
        $this->assertStringContainsString('This is a public and legitimate text file.', $result);
    }
}
