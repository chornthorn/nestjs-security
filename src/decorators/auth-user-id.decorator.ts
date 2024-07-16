import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UserSessionId } from '../types/user-session.interface';

/**
 * Custom parameter decorator to extract the user ID from the request object.
 * This decorator can be used in NestJS controllers to easily access the authenticated user's ID
 * from the request made to the server. It leverages NestJS's execution context and parameter decorator
 * capabilities to extract the user ID.
 *
 * @param {unknown} data - The data argument is not used but is required by the createParamDecorator signature.
 * @param {ExecutionContext} ctx - The execution context of the request, provided by NestJS, used to access the request object.
 * @returns {Pick<UserSession, 'id'>} An object containing the user's ID if available in the request's user object; otherwise, undefined.
 */
export const AuthUserId = createParamDecorator(
  (_: unknown, ctx: ExecutionContext): UserSessionId => {
    const request = ctx.switchToHttp().getRequest();
    return request?.user?.id;
  },
);
