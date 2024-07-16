import { applyDecorators, UseGuards } from '@nestjs/common';
import { ApiBearerAuth } from '@nestjs/swagger';
import { AccessAuthGuard } from '../guards/access.auth.guard';

const Auth = () => {
  return applyDecorators(ApiBearerAuth(), UseGuards(AccessAuthGuard));
};

export { Auth };
