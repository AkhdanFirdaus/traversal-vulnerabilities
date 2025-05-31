<?php

namespace Tests;

class Cwe23RelativePathTraversalTest extends BaseVulnerableScript
{
    public function testDoubleDotSlash(): void
    {
        $result = $this->reader->read('../../secret_dir/secret.txt');
        $this->assertStringNotContainsString('TOP SECRET', $result);
    }

    public function testDotDotBackslash(): void
    {
        $result = $this->reader->read('..\\..\\secret_dir\\secret.txt');
        $this->assertStringNotContainsString('TOP SECRET', $result);
    }
}
