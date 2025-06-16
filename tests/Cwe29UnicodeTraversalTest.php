<?php

namespace Tests;

use App\VulnFileRead;
use PHPUnit\Framework\TestCase;

class Cwe29UnicodeTraversalTest extends TestCase
{
    protected VulnFileRead $reader;

    protected function setUp(): void
    {
        $this->reader = new VulnFileRead();
    }
    
    public function testUnicodeTraversal(): void
    {
        $unicodeInput = html_entity_decode('%u002e%u002e%u002fsecret_dir/secret.txt', ENT_QUOTES);
        $result = $this->reader->read($unicodeInput);
        $this->assertStringNotContainsString('TOP SECRET', $result);
    }
}
