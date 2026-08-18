<?php

namespace GeneroWP\SecurityHardening;

interface Module
{
    /**
     * Register this module's hooks.
     */
    public function register(): void;
}
