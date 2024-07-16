import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UserSession } from '../types/user-session.interface';

/**
 * Custom parameter decorator for extracting the authenticated user's information from the request object.
 * This decorator simplifies the process of accessing the user's details in controller methods by automatically
 * parsing the request object to extract user information. It specifically retrieves the user's ID from the `sub`
 * property and includes all other properties of the user object.
 *
 * @param _data - Unused parameter, present to comply with the createParamDecorator signature.
 * @param ctx - The execution context of the request, provided by NestJS. It is used to access the request object.
 * @returns {UserSession} - An object containing the authenticated user's ID (extracted from `user.sub`) and all other
 *                         user properties spread into this object.
 */
export const AuthUser = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): UserSession => {
    const request = ctx.switchToHttp().getRequest();
    const { user } = request;
    return {
      id: user.sub,
      ...user,
    };
  },
);
