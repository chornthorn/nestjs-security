import { applyDecorators, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { AccessAuthGuard } from '../guards/access.auth.guard';

/**
 * Custom decorator for requiring authentication on NestJS routes.
 * This decorator applies the `AccessAuthGuard` to the route it decorates, enforcing authentication.
 * Optionally, it can also enable Swagger's ApiBearerAuth decorator to add bearer token authentication
 * documentation to the Swagger UI for the route.
 *
 * @param params - An optional configuration object.
 * @param params.enabledApi - If true, enables Swagger ApiBearerAuth documentation for the route. Defaults to true.
 * @returns A decorator that applies the necessary guards and, optionally, Swagger documentation enhancements.
 */
const RequiredAuth = (params?: { enabledApi: boolean; tag?: string }) => {
  const { enabledApi = true, tag } = params; // Default to true if not provided

  // Create an array to hold the decorators to apply
  const decorators = [];

  // Always apply the AccessAuthGuard
  decorators.push(UseGuards(AccessAuthGuard));

  // Optionally apply the ApiBearerAuth decorator for Swagger documentation
  if (tag) {
    decorators.push(ApiTags(tag));
  }

  // Optionally apply the ApiBearerAuth decorator for Swagger documentation
  if (enabledApi) {
    decorators.push(ApiBearerAuth());
  }

  // Return the combined decorators
  return applyDecorators(...decorators);
};

export { RequiredAuth };
