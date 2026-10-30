<?php

namespace Tests\Support;

class WakeupProbe
{
    public static bool $woken = false;

    public function __wakeup(): void
    {
        self::$woken = true;
    }
}
