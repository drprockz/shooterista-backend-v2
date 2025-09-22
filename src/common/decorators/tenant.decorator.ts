import { SetMetadata } from '@nestjs/common';

export const TENANT_REQUIRED_KEY = 'tenantRequired';

export const RequireTenant = () => SetMetadata(TENANT_REQUIRED_KEY, true);
