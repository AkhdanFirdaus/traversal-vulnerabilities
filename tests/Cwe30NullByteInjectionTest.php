<?php

namespace Tests;

class Cwe30NullByteInjectionTest extends BaseVulnerableScript
{
    public function testNullByteTraversal(): void
    {
        $result = $this->reader->read("../../etc/passwd%00.png");
        $this->assertStringNotContainsString('root:x:0:0:', $result, 'Path traversal should not allow access to /etc/passwd');
    }
}
