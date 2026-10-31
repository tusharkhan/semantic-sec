<?php

declare(strict_types=1);

// Recommended model per provider, refreshed each release; null means config must name one.
return [
    'models' => [
        'anthropic' => 'claude-opus-5-5',
        'openai' => 'gpt-6-astra',
        'ollama' => null,
    ],
];
