import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { Reflector } from '@nestjs/core';
import { UserSession } from '../types/user-session.interface';
import {
  ALLOW_ANONYMOUS_METADATA,
  ROLE_METADATA,
} from '../constants/security.constant';
import { SecurityService } from '../security.service';

/**
 * RoleAuthGuard is a custom guard that implements the CanActivate interface.
 * It verifies if a user has the required roles to access a route or if the route
 * allows anonymous access.
 */
@Injectable()
export class RoleAuthGuard implements CanActivate {
  /**
   * Constructs the RoleAuthGuard.
   * @param {Reflector} reflector - The Reflector instance used to read metadata.
   * @param {SecurityService} securityService - The SecurityService instance used to check user roles.
   */
  constructor(
    private readonly reflector: Reflector,
    private readonly securityService: SecurityService,
  ) {}

  /**
   * Determines whether the current request is allowed to proceed based on user roles
   * and route metadata.
   * @param {ExecutionContext} context - The execution context of the current request.
   * @returns {boolean | Promise<boolean> | Observable<boolean>} Whether the request is allowed to proceed.
   * @throws {ForbiddenException} If the user is not authorized to access the resource.
   */
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    // Check if the route allows access by anonymous users
    const allowAnonymous = this.securityService.checkAllowAnonymous({
      context,
      reflector: this.reflector,
    });

    // If the route allows anonymous access, always allow access
    if (allowAnonymous) return true;

    // Get the forbidden message from the security service
    const { forbidden: forbiddenMessage = 'Forbidden' } =
      this.securityService.messages;

    // Retrieve the user from the execution context
    const request = context.switchToHttp().getRequest();
    const { user }: { user: UserSession } = request;

    // If the user is not found, throw an error
    if (!user) {
      throw new ForbiddenException(forbiddenMessage);
    }

    // Get the admin role from the security service
    const adminRole = this.securityService.adminRole;

    // Check if the user has the 'Admin' role and always allow access if true
    const isAdmin = () => user.roles?.includes(adminRole);
    if (isAdmin()) return true;

    // Get the role configuration from the security service
    const roleConfig = this.securityService.roles;

    // Retrieve roles from metadata
    const roles = this.reflector.getAllAndOverride<typeof roleConfig>(
      ROLE_METADATA,
      [context.getHandler(), context.getClass()],
    );

    // If the user has the necessary roles, allow access
    if (roles.some((role) => user.roles?.includes(role))) return true;

    // If the user does not have the necessary roles, throw an error
    throw new ForbiddenException(forbiddenMessage);
  }
}
