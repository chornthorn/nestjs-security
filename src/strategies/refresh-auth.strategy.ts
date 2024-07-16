import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { REFRESH_AUTH_GUARD } from '../constants/security.constant';
import { SecurityService } from '../security.service';

/**
 * Defines the strategy for refresh token authentication using Passport and JWT.
 *
 * This class extends the PassportStrategy by implementing a JWT strategy specific for refresh tokens.
 * Decorated with `@Injectable()`, it allows NestJS to manage its lifecycle. The strategy is configured
 * to extract JWTs from the authorization header as bearer tokens, focusing on refresh tokens specifically.
 * It uses the public key of the RSA key pair designated for 'refresh-token' to verify the token's signature
 * and specifies the algorithm used for token verification.
 *
 * The constructor initializes the strategy with specific options for handling refresh tokens, including
 * the method to extract the token from requests, the key for verifying the token's signature, and the
 * algorithm expected to be used in the token's signature.
 */
@Injectable()
export class RefreshAuthStrategy extends PassportStrategy(
  Strategy,
  REFRESH_AUTH_GUARD,
) {
  constructor(private readonly _service: SecurityService) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: _service.options.jwt?.ignoreExpiration ?? false,
      passReqToCallback: _service.options.jwt?.passReqToCallback ?? true,
      secretOrKey: _service.rsaKeys('refresh-token').publicKey,
      algorithms: [_service.rsaKeys('refresh-token').algorithm],
    });
  }
}
