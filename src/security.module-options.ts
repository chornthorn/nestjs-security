/**
 * Type definition for RSA key types.
 *
 * Specifies the allowed types of RSA keys within the security module,
 * limiting them to either 'access-token' or 'refresh-token'.
 */
export type RSAKeyType = 'access-token' | 'refresh-token';

/**
 * Interface for RSA key options.
 *
 * Defines the structure for RSA key configurations, including the key name,
 * optional algorithm, and the key pair (private and public keys).
 *
 * @property {RSAKeyType} name - The type of the RSA key, restricted to either 'access-token' or 'refresh-token'.
 * @property {string} [algorithm] - Optional. The RSA algorithm to be used, can be 'RS256', 'RS384', or 'RS512'.
 * @property {string} privateKey - The RSA private key as a string.
 * @property {string} publicKey - The RSA public key as a string.
 */
export interface RSAOptions {
  name: RSAKeyType;
  algorithm?: 'RS256' | 'RS384' | 'RS512';
  privateKey: string;
  publicKey: string;
}

/**
 * Interface for HMAC options.
 *
 * Specifies the HMAC algorithm and secret key to be used for HMAC-based operations within the security module.
 *
 * @property {string} algorithm - The HMAC algorithm to be used.
 * @property {string} secret - The secret key for HMAC operations.
 */
interface HMACOptions {
  algorithm: string;
  secret: string;
}

/**
 * Interface for roles options.
 *
 * Defines the structure for role configurations, including an admin role and an array of additional roles.
 *
 * @property {string} admin - The identifier for the admin role.
 * @property {Array<'Admin' | string>} roles - An array of additional roles.
 */
interface RolesOptions {
  admin: string;
  roles: string[];
}

/**
 * Interface for JWT options.
 *
 * Specifies the options for JWT configurations within the security module, including whether to ignore expiration
 * dates, whether to pass the request object to the callback function, and any additional options.
 *
 * @property {boolean} [ignoreExpiration] - Optional. Whether to ignore expiration dates for JWT tokens.
 * @property {boolean} [passReqToCallback] - Optional. Whether to pass the request object to the callback function.
 **/
interface JWTOptions {
  ignoreExpiration?: boolean;
  passReqToCallback?: boolean;
}

export interface SecurityModuleOptions {
  jwt?: JWTOptions;
  customMessage?: {
    unauthorized?: string;
    forbidden?: string;
    invalidToken?: string;
  };
  hmac?: HMACOptions;
  roleConfig?: RolesOptions;
  secret?: {
    accessToken: string;
    refreshToken: string;
  };
  useRSAInsteadOfSecret?: boolean;
  rsa?: [RSAOptions, RSAOptions?];
}
