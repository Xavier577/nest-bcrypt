import { DynamicModule, Module } from '@nestjs/common';
import { BcryptModuleOptions } from './types';
import { BcryptService } from './bcrypt.service';
import { BCRYPT_MODULE_OPTIONS } from './symbols';

@Module({
  providers: [BcryptService],
})
export class BcryptModule {
  static register(options: BcryptModuleOptions): DynamicModule {
    return {
      module: BcryptModule,
      providers: [
        {
          provide: BCRYPT_MODULE_OPTIONS,
          useValue: options,
        },
        BcryptService,
      ],
      exports: [BcryptService],
    };
  }
}
