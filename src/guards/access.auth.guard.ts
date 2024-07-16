import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { Observable } from 'rxjs';
import { Reflector } from '@nestjs/core';
import { ACCESS_AUTH_GUARD } from '../constants/security.constant';
import { SecurityService } from '../security.service';

/**
 * AccessAuthGuard is a custom authentication guard that extends the default
 * AuthGuard provided by @nestjs/passport. It adds functionality to allow anonymous
 * access to certain routes based on metadata.
 */
@Injectable()
export class AccessAuthGuard extends AuthGuard(ACCESS_AUTH_GUARD) {
  /**
   * Constructor for the AccessAuthGuard.
   * @param {Reflector} reflector - The Reflector instance used to read metadata.
   * @param {SecurityService} securityService - The SecurityService instance used to check for anonymous access.
   */
  constructor(
    private readonly reflector: Reflector,
    private readonly securityService: SecurityService,
  ) {
    super();
  }

  /**
   * Determines whether the current request is allowed to proceed.
   * This method checks for the ALLOW_ANONYMOUS_METADATA metadata to decide if the request
   * can bypass authentication.
   * @param {ExecutionContext} context - The execution context of the current request.
   * @returns {boolean | Promise<boolean> | Observable<boolean>} Whether the request is allowed to proceed.
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

    // Proceed with authentication
    return super.canActivate(context);
  }

  /**
   * Handles the request after authentication.
   * This method throws an UnauthorizedException if there is an error or if the user is not authenticated.
   * @param {any} err - The error object, if any.
   * @param {any} user - The authenticated user object, if any.
   * @returns {any} The authenticated user object.
   * @throws {UnauthorizedException} If the user is not authenticated or if there is an error.
   */
  handleRequest(err: any, user: any): any {
    // get the custom error messages from the SecurityService
    const { unauthorized = 'Unauthorized' } = this.securityService.messages;

    if (err || !user) {
      throw err || new UnauthorizedException(unauthorized);
    } else {
      return user;
    }
  }
}
