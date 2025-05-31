<?php

namespace Tests;

use App\UserProfileRead;
use PHPUnit\Framework\TestCase;

class Cwe639AuthorizationBypassTest extends TestCase
{
    protected UserProfileRead $reader;

    protected function setUp(): void
    {
        $this->reader = new UserProfileRead();
    }

    public function testAccessOwnProfile(): void
    {
        $result = $this->reader->getProfileByUserId('1');
        $this->assertStringContainsString('User 1 profile', $result);
    }

    public function testAccessAnotherUserProfile(): void
    {
        // Simulate ID tampering, should still work (vulnerable)
        $result = $this->reader->getProfileByUserId('2');
        $this->assertStringContainsString('User 2 profile', $result);
    }

    public function testAccessHighPrivilegedUser(): void
    {
        // Simulate unauthorized access
        $result = $this->reader->getProfileByUserId('9999');
        $this->assertNotEquals('Top secret profile', $result);
    }
}
