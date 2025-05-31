<?php

namespace Tests;

class BasicFunctionalityTest extends BaseVulnerableScript
{
    public function testCanReadSafeFile(): void
    {
        $content = $this->reader->read('safe_dir/legit.txt');
        $this->assertStringContainsString('legit', $content);
    }

    public function testCannotReadSecretFile(): void
    {
        $content = $this->reader->read('../secret_dir/secret.txt');
        $this->assertEquals('Access denied', $content);
    }
}
