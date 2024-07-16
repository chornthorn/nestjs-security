/**
 * Type definition for generic session identifiers.
 * This type allows session identifiers to be either a string or a number.
 */
type generic = string | number;

/**
 * Default type for session identifiers, set to string.
 */
type defaultGeneric = string;

/**
 * Interface for UserSession objects.
 * This interface defines the structure of a user session, including the session identifier,
 * username, and roles. It uses a generic type for the session identifier, which can be either
 * a string or a number, with a default of string. Additional properties can be added dynamically.
 *
 * @template SessionId - A generic type parameter constrained to `string` or `number`, representing the unique identifier of the user session.
 * @property {SessionId} id - The unique identifier of the user session.
 * @property {string} username - The username associated with the user session.
 * @property {Role[]} roles - An array of roles assigned to the user.
 * @property {[key: string]: any} ... - Additional dynamic properties that can be added to the user session object.
 */
interface UserSession<SessionId extends generic = defaultGeneric> {
  id: SessionId;
  username: string | null;
  roles: string[];
  [key: string]: any;
}

/**
 * Utility type to pick the 'id' property from the UserSession interface.
 * This type is useful for functions or components that only need access to the user's session ID.
 *
 * @template SessionId - Inherits the generic constraint from UserSession, allowing `string` or `number`.
 */
type UserSessionId<SessionId extends generic = defaultGeneric> = Pick<
  UserSession<SessionId>,
  'id'
>;

export { UserSession, UserSessionId };
