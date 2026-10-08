<?php

$EM_CONF[$_EXTKEY] = [
    'title' => 'OIDC Connect',
    'description' => 'OpenID Connect login for frontend and backend, configured per site via Site Settings.',
    'category' => 'services',
    'author' => 'Sven Wappler',
    'author_email' => 'typo3@wappler.systems',
    'author_company' => 'WapplerSystems',
    'state' => 'beta',
    'version' => '0.2.0',
    'constraints' => [
        'depends' => [
            'typo3' => '14.0.0-14.99.99',
            'php' => '8.2.0-8.5.99',
        ],
    ],
];
