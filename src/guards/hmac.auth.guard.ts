import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { SecurityService } from '../security.service';

@Injectable()
export class HmacAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly securityService: SecurityService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if the route allows access by anonymous users
    this.securityService.checkAllowAnonymous({
      context,
      reflector: this.reflector,
    });

    const request = context.switchToHttp().getRequest();
    const { body } = request;
    const { hash, data } = body;

    if (!hash || !data) {
      throw new BadRequestException('The body should contain a hash and data');
    }

    // Get the algorithm and secret from the configuration
    const { algorithm = 'sha256', secret } = this.securityService.options?.hmac;

    if (!secret) {
      throw new InternalServerErrorException('HMAC secret is not configured');
    }

    // Create the HMAC hash
    this.createHmac(data, secret, algorithm);

    // Validate the HMAC hash
    return this.validateHmac(hash, data);
  }

  // Validate the HMAC hash
  private validateHmac(hash: string, data: string): boolean {
    try {
      return this.securityService.verifyHmac({
        clientHash: hash,
        serverHash: data,
      });
    } catch (error) {
      throw new UnauthorizedException();
    }
  }

  // Create the HMAC hash
  private createHmac(data: string, secret: string, algorithm: string): void {
    const hmacCreated = this.securityService.createHmac({
      text: data,
      secret,
      algorithm,
    });

    if (!hmacCreated) {
      throw new UnauthorizedException();
    }
  }
}
