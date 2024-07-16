import { ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { JwtService, JwtSignOptions, JwtVerifyOptions } from '@nestjs/jwt';
import { MODULE_OPTIONS_TOKEN } from './security.module-definition';
import {
  RSAKeyType,
  RSAOptions,
  SecurityModuleOptions,
} from './security.module-options';
import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import { Reflector } from '@nestjs/core';
import { ALLOW_ANONYMOUS_METADATA } from './constants/security.constant';

/**
 * The `SecurityService` class provides a comprehensive suite of security-related functionalities,
 * including JWT management, password hashing and verification, and HMAC creation and verification.
 * It leverages NestJS's dependency injection system to access application-wide security settings and utilities,
 * such as `JwtService` for JWT operations and bcrypt for hashing.
 *
 * @Injectable() - Marks the class as a provider that can be injected within the NestJS framework,
 * allowing it to be used across the application wherever security operations are needed.
 */
@Injectable()
export class SecurityService {
  /**
   * Constructs a new instance of the SecurityService.
   * This constructor injects module options and the JWT service into the service,
   * enabling it to use these injected services and configurations throughout its methods.
   *
   * @param _options - The security module options provided through dependency injection.
   * @param jwtService - The JwtService instance provided by `@nestjs/jwt` for handling JWT operations.
   */
  constructor(
    @Inject(MODULE_OPTIONS_TOKEN)
    private readonly _options: SecurityModuleOptions,
    private readonly jwtService: JwtService,
  ) {}

  /**
   * Getter for the security module options.
   * This property allows access to the security module options that were provided during the instantiation of the SecurityService.
   * These options include configurations necessary for the security operations within the service.
   *
   * @returns {SecurityModuleOptions} The security module options.
   */
  get options(): SecurityModuleOptions {
    return this._options;
  }

  /**
   * Generates a JWT (JSON Web Token) with the specified payload and options.
   * This method utilizes the JwtService from NestJS to asynchronously sign the payload,
   * allowing for custom options such as token expiration or audience to be specified.
   *
   * @param params - The parameters for generating the JWT.
   * @param params.payload - The payload to be included in the JWT, typically containing the subject (sub) and other claims.
   * @param params.options - (Optional) Additional options for the JWT, such as `expiresIn` or `audience`.
   * @returns {Promise<string>} - A promise that resolves to the generated JWT as a string.
   */
  createJwt(params: {
    payload: { sub: string } & Record<string, any>;
    options?: JwtSignOptions;
  }): Promise<string> {
    const { payload, options } = params;
    return this.jwtService.signAsync(payload, options);
  }

  /**
   * Verifies the authenticity of a JWT using the provided token and options.
   * This method leverages the JwtService from NestJS to verify the token's signature and payload,
   * ensuring that the token is valid and has not been tampered with.
   *
   * @param params - The parameters for verifying the JWT.
   * @param params.token - The JWT token to verify.
   * @param params.options - The options used to verify the JWT, such as the public key or supported algorithms.
   * @returns {Promise<any>} - A promise that resolves to the decoded payload of the JWT if it is valid.
   */
  verifyJwt(params: {
    token: string;
    options: JwtVerifyOptions;
  }): Promise<any> {
    const { token, options } = params;
    return this.jwtService.verifyAsync(token, options);
  }

  /**
   * Creates a hash of the given text using bcrypt.
   * This function allows for hashing a given text with a specified number of salt rounds or a salt string.
   * The saltOrRounds parameter determines the computational complexity of the hash: a higher value means a more secure hash but requires more processing time.
   * If saltOrRounds is not provided, it defaults to 10.
   *
   * @param params - The parameters for hashing the text.
   * @param params.text - The text to be hashed.
   * @param params.saltOrRounds - (Optional) The salt string or the number of rounds for generating the salt. Defaults to 10.
   * @returns A promise that resolves to the hash of the given text.
   */
  createHash(params: { text: string; saltOrRounds?: string | number }) {
    const { text, saltOrRounds = 10 } = params; // Default saltOrRounds is 10
    return bcrypt.hash(text, saltOrRounds);
  }

  /**
   * Verifies if the given plaintext matches the provided hash using bcrypt.
   * This method is useful for validating user passwords or other sensitive data against stored hashes in a secure manner.
   *
   * @param params - An object containing the plaintext and hash to compare.
   * @param params.plaintext - The plaintext value to verify.
   * @param params.hash - The hash against which the plaintext is to be verified.
   * @returns {Promise<boolean>} - A promise that resolves to `true` if the plaintext matches the hash, otherwise `false`.
   */
  verifyHash(params: { plaintext: string; hash: string }): Promise<boolean> {
    const { plaintext, hash } = params;
    return bcrypt.compare(plaintext, hash);
  }

  /**
   * Creates an HMAC (Hash-based Message Authentication Code) using the specified text, secret, and algorithm.
   * This method first converts the input text into a JSON string, then encodes it in base64 before generating the HMAC.
   * The default algorithm used is 'sha512', but this can be overridden by specifying a different algorithm in the parameters.
   *
   * @param params - The parameters for creating the HMAC.
   * @param params.text - The input text to be hashed.
   * @param params.secret - The secret key used for hashing.
   * @param params.algorithm - (Optional) The hashing algorithm to use. Defaults to 'sha512'.
   * @returns {string} - The generated HMAC as a hexadecimal string.
   */
  createHmac(params: {
    text: string;
    secret: string;
    algorithm?: string;
  }): string {
    const { text, secret, algorithm = 'sha512' } = params; // Default algorithm is 'sha512'

    // Convert the input text to a JSON string and encode it in base64
    const json = JSON.stringify(text);
    const value = Buffer.from(json).toString('base64');

    // Generate the HMAC
    return crypto.createHmac(algorithm, secret).update(value).digest('hex');
  }

  /**
   * Verifies if the client's HMAC matches the server's HMAC using a timing-safe comparison.
   * This method is designed to prevent timing attacks by ensuring that the time it takes to compare
   * two hashes does not depend on the number of characters that match.
   *
   * @param params - An object containing the clientHash and serverHash.
   * @param params.clientHash - The HMAC hash generated by the client.
   * @param params.serverHash - The HMAC hash generated by the server to compare against.
   * @returns {boolean} - Returns `true` if the hashes match, otherwise `false`.
   */
  verifyHmac(params: { clientHash: string; serverHash: string }): boolean {
    const { clientHash, serverHash } = params;

    // Convert the client and server hashes from strings to Buffers for a timing-safe comparison
    const client = Buffer.from(clientHash);
    const server = Buffer.from(serverHash);

    // Use crypto.timingSafeEqual to compare the hashes in a way that prevents timing attacks
    return crypto.timingSafeEqual(client, server);
  }

  /**
   * Checks if a route allows anonymous access based on metadata.
   * This method utilizes the `Reflector` to retrieve custom metadata (`ALLOW_ANONYMOUS_METADATA`)
   * applied to route handlers or controllers. It's primarily used in guards to determine if a request
   * can bypass authentication checks, allowing for public access to certain routes.
   *
   * @param params - An object containing the execution context and reflector.
   * @param params.context - The execution context of the current request, providing access to route handlers and controllers.
   * @param params.reflector - The `Reflector` instance used to access metadata applied to the route handlers or controllers.
   * @returns {boolean} - Returns `true` if the route allows anonymous access, otherwise `false`.
   */
  checkAllowAnonymous(params: {
    context: ExecutionContext;
    reflector: Reflector;
  }): boolean {
    const { context, reflector } = params;
    return reflector.getAllAndOverride<boolean>(ALLOW_ANONYMOUS_METADATA, [
      context.getHandler(),
      context.getClass(),
    ]);
  }

  /**
   * Getter for custom error messages.
   * This property provides access to custom error messages defined in the security module options.
   * If no custom error messages are defined, it returns an empty object.
   *
   * @returns {typeof this.options.customErrorMessage} The custom error messages if defined, otherwise an empty object.
   */
  get messages(): typeof this.options.customMessage {
    return this.options.customMessage || {};
  }

  /**
   * Getter for the roles defined in the security module options.
   * This property provides access to the roles configuration, allowing retrieval of the roles array.
   * If no roles are defined in the configuration, it defaults to an empty array.
   *
   * @returns {Array<string>} An array of roles defined in the security module options, or an empty array if none are defined.
   */
  get roles(): typeof this.options.roleConfig.roles {
    return this.options.roleConfig.roles || [];
  }

  /**
   * Getter for the admin role defined in the security module options.
   * This property provides access to the admin role configuration, allowing retrieval of the admin role string.
   * If no admin role is defined in the configuration, it defaults to an empty string.
   *
   * @returns {string} The admin role defined in the security module options, or an empty string if none is defined.
   */
  get adminRole(): string {
    return this.options.roleConfig.admin || '';
  }

  /**
   * Retrieves RSA key options for a specified key name and converts the keys from base64 to UTF-8 format.
   * This method searches the RSA key configurations for a key matching the provided name. If found, it converts
   * the base64-encoded private and public keys into UTF-8 strings. This is useful for operations that require
   * RSA keys in a readable format. If the specified key is not found, an `InternalServerErrorException` is thrown.
   *
   * @param keyName - The name of the RSA key to retrieve and convert.
   * @returns {RSAOptions} An object containing the RSA key options with the private and public keys in UTF-8 format.
   * @throws {Error} If the specified RSA key name is not found in the configuration.
   */
  rsaKeys(keyName: RSAKeyType): RSAOptions {
    const rsa = this.options.rsa.find((rsa) => rsa.name === keyName);

    if (!rsa) {
      throw new Error(`RSA key '${keyName}' not found in configuration`);
    }

    // Convert base64 to RSA key
    const convertor = (key: string) => {
      return Buffer.from(key, 'base64').toString('utf-8');
    };

    // Convert the base64-encoded private and public keys to UTF-8 strings
    const privateKey = convertor(rsa.privateKey);
    const publicKey = convertor(rsa.publicKey);

    // Return the RSA key options with the converted keys
    return {
      ...rsa,
      privateKey,
      publicKey,
    };
  }
}
