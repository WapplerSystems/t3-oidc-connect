<?php

declare(strict_types=1);

namespace WapplerSystems\OidcConnect\ViewHelpers;

use Psr\Http\Message\ServerRequestInterface;
use TYPO3Fluid\Fluid\Core\ViewHelper\AbstractViewHelper;

/**
 * Reads a query parameter, reduced to `[a-z_]` so it is safe to use as part
 * of a translation key (`?oidc_error=<code>`).
 *
 * @internal
 */
final class RequestParameterViewHelper extends AbstractViewHelper
{
    public function initializeArguments(): void
    {
        $this->registerArgument('name', 'string', 'Query parameter name', true);
    }

    public function render(): string
    {
        if (!$this->renderingContext->hasAttribute(ServerRequestInterface::class)) {
            return '';
        }
        $value = $this->renderingContext->getAttribute(ServerRequestInterface::class)->getQueryParams()[$this->arguments['name']] ?? '';
        return is_string($value) ? (string)preg_replace('/[^a-z_]/', '', $value) : '';
    }
}
