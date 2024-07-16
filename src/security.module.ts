import { Module } from '@nestjs/common';
import { SecurityService } from './security.service';
import { JwtModule } from '@nestjs/jwt';
import { ConfigurableModuleClass } from './security.module-definition';
import { AccessAuthStrategy } from './strategies/access-auth.strategy';
import { RefreshAuthStrategy } from './strategies/refresh-auth.strategy';

/**
 * Defines the `SecurityModule` module for the application's security features.
 *
 * This module integrates JWT (JSON Web Tokens) for authentication and authorization purposes,
 * leveraging NestJS's `JwtModule` for token management. It registers the `JwtModule` with default
 * configurations, which can be customized as needed.
 *
 * The `SecurityService` is also exported to be available for use in other modules within the application.
 *
 * Inherits from `ConfigurableModuleClass` to allow for module customization through dynamic module properties.
 */
@Module({
  imports: [JwtModule.register({})],
  providers: [SecurityService, AccessAuthStrategy, RefreshAuthStrategy],
  exports: [SecurityService],
})
export class SecurityModule extends ConfigurableModuleClass {}
