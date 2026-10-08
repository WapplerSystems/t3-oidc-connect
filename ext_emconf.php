<?php

$EM_CONF[$_EXTKEY] = [
    'title' => 'OIDC Connect',
    'description' => 'TYPO3 v14 OpenID Connect with per-site settings and context variants. Successor of causal/oidc and wapplersystems/oidc-addons.',
    'category' => 'services',
    'author' => 'Sven Wappler',
    'author_email' => 'info@wappler.systems',
    'state' => 'alpha',
    'version' => '0.1.0',
    'constraints' => [
        'depends' => [
            'typo3' => '14.0.0-14.99.99',
        ],
    ],
];
