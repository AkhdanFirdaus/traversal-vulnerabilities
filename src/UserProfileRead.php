<?php

namespace App;

class UserProfileRead
{
    public function getProfileByUserId(string $userId): string
    {
        // ❗ Vulnerable: does not check ownership or session
        $base = __DIR__ . '/../vulnerable_files/users/';
        $path = realpath($base . $userId . '/profile.txt');

        if ($path && str_starts_with($path, realpath($base))) {
            return file_get_contents($path);
        }

        return 'Profile not found or access denied';
    }
}
