<?php

namespace Tests;

class Cwe22PathTraversalTest extends BaseVulnerableScript
{
    public function testPathTraversalEscape(): void
    {
        $attempt = $this->reader->read('../../../../etc/passwd');
        $this->assertStringNotContainsString('root:x:0:0:', $attempt, 'Path traversal should not allow access to /etc/passwd');
    }
}
