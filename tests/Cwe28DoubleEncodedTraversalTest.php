<?php

namespace Tests;

class Cwe28DoubleEncodedTraversalTest extends BaseVulnerableScript
{
    public function testDoubleEncodedPasswd(): void
    {
        $encoded = urldecode(urldecode('%252e%252e%252fetc/passwd'));
        $result = $this->reader->read($encoded);
        $this->assertStringNotContainsString('root:x:0:0:', $result, 'Path traversal should not allow access to /etc/passwd');
    }

    public function testDoubleEncodedSecret(): void
    {
        $encoded = urldecode(urldecode('%255c%255csecret_dir\\secret.txt'));
        $result = $this->reader->read($encoded);
        $this->assertStringNotContainsString('TOP SECRET', $result);
    }
}
