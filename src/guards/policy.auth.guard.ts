import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Observable } from 'rxjs';
import { SecurityService } from '../security.service';

@Injectable()
export class PolicyAuthGuard implements CanActivate {
  constructor(private readonly securityService: SecurityService) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    throw new Error('Method not implemented.');
  }
}
