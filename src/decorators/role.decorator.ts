import { SetMetadata } from '@nestjs/common';
import { ROLE_METADATA } from '../constants/security.constant';

/**
 * A decorator that assigns roles to NestJS route handlers.
 *
 * Utilizes the `SetMetadata` function from NestJS common module to associate
 * metadata with the route handler. The metadata is used for role-based access control.
 *
 * @param roles - A list of roles as strings. These roles are used to control access
 * to the route handler.
 * @returns A decorator function that applies the specified roles to the route handler.
 */
export const Role = (...roles: string[]) => SetMetadata(ROLE_METADATA, roles);
