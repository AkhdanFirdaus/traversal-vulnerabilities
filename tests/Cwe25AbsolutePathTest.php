<?php
namespace Tests;

class Cwe25AbsolutePathTest extends BaseVulnerableScript
{
    public function testUnixAbsolutePath(): void
    {
        $result = $this->reader->read('/etc/passwd');
        $this->assertNotEmpty($result);
    }

    public function testWindowsAbsolutePath(): void
    {
        $result = $this->reader->read('C:\\Windows\\System32\\drivers\\etc\\hosts');
        $this->assertNotEmpty($result);
    }
}
?>