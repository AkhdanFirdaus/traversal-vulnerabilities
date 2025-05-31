<?php

namespace Tests;

class Cwe27FolderUpOneLevelTest extends BaseVulnerableScript
{
    public function testImagesFolderDotDot(): void
    {
        $result = $this->reader->read('safe_dir/images/../legit.txt');
        $this->assertStringStartsWith('This is a public and legitimate text file.', $result);
    }

    public function testUploadsFolderDotDot(): void
    {
        $result = $this->reader->read('safe_dir/images/../modules/public_module.php');
        $this->assertStringContainsString('<?php', $result);
    }
}
