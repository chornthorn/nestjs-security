import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ACCESS_AUTH_GUARD } from '../constants/security.constant';
import { SecurityService } from '../security.service';

/**
 * Defines the strategy for access token authentication using Passport and JWT.
 *
 * This class extends the PassportStrategy by implementing a JWT strategy specific for access tokens.
 * It is decorated with `@Injectable()` to allow NestJS to manage its lifecycle. The strategy is configured
 * to extract JWTs from the authorization header as bearer tokens. It uses RSA keys specific to 'access-token'
 * for verifying the token's signature and its algorithm.
 *
 * The `validate` method is an async function that processes the payload of a valid JWT, returning a user object
 * or throwing an exception if the token is invalid. This method can be customized to include additional validation
 * logic as needed.
 *
 * @extends PassportStrategy(Strategy, ACCESS_AUTH_GUARD)
 */
@Injectable()
export class AccessAuthStrategy extends PassportStrategy(
  Strategy,
  ACCESS_AUTH_GUARD,
) {
  constructor(private readonly _service: SecurityService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: _service.options.jwt?.ignoreExpiration ?? false,
      passReqToCallback: _service.options.jwt?.passReqToCallback ?? true,
      secretOrKey: _service.rsaKeys('access-token').privateKey,
      algorithms: [_service.rsaKeys('access-token').algorithm],
    });
  }

  /**
   * Validates the JWT payload.
   *
   * This method is called after the JWT has been verified and decodes the payload. It should return a user object
   * based on the payload's information. This implementation simply returns the payload with an added `id` property,
   * but it can be extended to include additional validation or transformation logic.
   *
   * @param request - The request object.
   * @param payload - The decoded JWT payload.
   * @returns The validated user object.
   */
  async validate(request: any, payload: any) {
    return {
      id: payload.sub,
      ...payload,
    };
  }
}
