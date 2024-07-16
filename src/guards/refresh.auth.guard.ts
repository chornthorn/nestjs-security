import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { REFRESH_AUTH_GUARD } from '../constants/security.constant';
import { SecurityService } from '../security.service';

/**
 * `RefreshAuthGuard` extends the NestJS `AuthGuard` to implement authentication specifically for refresh token functionality.
 * This guard is used to protect routes that require a valid refresh token for access. It leverages the `REFRESH_AUTH_GUARD`
 * strategy, which should be defined separately to handle the validation of refresh tokens.
 *
 * The `@Injectable()` decorator marks this class as a provider, allowing it to be injected into controllers or other providers
 * within the NestJS application. This enables the application to utilize the custom refresh token authentication strategy
 * defined in `REFRESH_AUTH_GUARD`.
 */
@Injectable()
export class RefreshAuthGuard extends AuthGuard(REFRESH_AUTH_GUARD) {
  constructor(private readonly securityService: SecurityService) {
    super();
  }

  handleRequest(err, user, info, context, status): any {
    const { unauthorized } = this.securityService.messages;

    if (err || !user) {
      throw err || new UnauthorizedException(unauthorized);
    }
    return user;
  }
}
