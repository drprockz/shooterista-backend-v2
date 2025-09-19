import { Module, Global } from '@nestjs/common';
import { queues } from './queues';
@Global()
@Module({
  providers: [{ provide: 'QUEUES', useValue: queues }],
  exports: ['QUEUES'],
})
export class BullInfraModule {}
