<?php

namespace Tests;

class Cwe29UnicodeTraversalTest extends BaseVulnerableScript
{
    public function testUnicodeTraversal(): void
    {
        $unicodeInput = html_entity_decode('%u002e%u002e%u002fsecret_dir/secret.txt', ENT_QUOTES);
        $result = $this->reader->read($unicodeInput);
        $this->assertStringNotContainsString('TOP SECRET', $result);
    }
}
