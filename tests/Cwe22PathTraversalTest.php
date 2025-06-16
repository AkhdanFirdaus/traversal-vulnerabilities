<?php

namespace Tests;

use App\VulnFileRead;
use PHPUnit\Framework\TestCase;

class Cwe22PathTraversalTest extends TestCase
{
    protected VulnFileRead $reader;

    protected function setUp(): void
    {
        $this->reader = new VulnFileRead();
    }
    
    public function testPathTraversalEscape(): void
    {
        $attempt = $this->reader->read('../../../../etc/passwd');
        $this->assertStringNotContainsString('root:x:0:0:', $attempt, 'Path traversal should not allow access to /etc/passwd');
    }
}
