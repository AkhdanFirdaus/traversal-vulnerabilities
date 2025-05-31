<?php

namespace Tests;

class Cwe26ObfuscatedTraversalTest extends BaseVulnerableScript
{
    public function testTripleDotTraversal(): void
    {
        $result = $this->reader->read('.../...//secret_dir/secret.txt');
        $this->assertStringNotContainsString('TOP SECRET', $result);
    }

    public function testTripleDotBackslashTraversal(): void
    {
        $result = $this->reader->read('...\\...\\\\secret_dir\\secret.txt');
        $this->assertStringNotContainsString('TOP SECRET', $result);
    }
}
