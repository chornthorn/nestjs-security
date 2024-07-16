import { SetMetadata } from '@nestjs/common';
import { ALLOW_ANONYMOUS_METADATA } from '../constants/security.constant';

/**
 * Decorator that marks a route handler as publicly accessible.
 * This decorator is used to allow anonymous access to a route handler
 * that would otherwise require authentication.
 */
export const AllowAnonymous = () => SetMetadata(ALLOW_ANONYMOUS_METADATA, true);
