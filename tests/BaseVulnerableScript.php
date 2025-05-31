<?php

namespace Tests;

use PHPUnit\Framework\TestCase;
use App\VulnFileRead;

abstract class BaseVulnerableScript extends TestCase
{
    protected VulnFileRead $reader;

    protected function setUp(): void
    {
        $this->reader = new VulnFileRead();
    }
}
