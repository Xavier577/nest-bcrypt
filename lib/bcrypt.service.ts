import { Inject, Injectable } from '@nestjs/common';
import { BCRYPT_MODULE_OPTIONS } from './symbols';
import { BcryptModuleOptions, BcryptSalt } from './types';
import * as bcrypt from 'bcrypt';

@Injectable()
export class BcryptService {
  private salt: BcryptSalt;

  constructor(
    @Inject(BCRYPT_MODULE_OPTIONS)
    private readonly options: BcryptModuleOptions,
  ) {
    this.salt = options.salt;
  }

  /**
   * @param data unencrypted data to make the comparisons against
   * @param hash encrypted hash to comare the data with
   * @example export class AuthenticationService {
   *        constructor(private readonly hasherService: HasherService) {}
   *
   *        public async comparePassword(data: { password: string; hashedPassword: string }) {
   *            // your logic above
   *            const passwdMatch = await this.hasherService.compare(data.password, data.hashedPassword);
   *
   *            if (!passwdMatch) {
   *                // your logic
   *                }
   *            }
   *    }
   */
  public async compare(data: string | Buffer, hash: string): Promise<boolean> {
    return bcrypt.compare(data, hash);
  }

  /**
   * @param data unencrypted data to make the comparisons against
   * @param hash encrypted hash to comare the data with
   * @example export class AuthenticationService {
   *        constructor(private readonly hasherService: HasherService) {}
   *
   *        public comparePassword(data: { password: string; hashedPassword: string }) {
   *            // your logic above
   *            const passwdMatch = this.hasherService.compareSync(data.password, data.hashedPassword);
   *
   *            if (!passwdMatch) {
   *                // your logic
   *                }
   *            }
   *    }
   */
  public compareSync(data: string | Buffer, hash: string): boolean {
    return bcrypt.compareSync(data, hash);
  }

  /**
   *
   * @param data The data to be encrypted.
   * @param salt to be used to hash the data. if not set would use the salt set from the HasherModule's register function
   * @returns A promise to be either resolved with the encrypted data salt or rejected with an Error
   * @example export class AuthenticationService {
   *        constructor(private readonly hasherService: HasherService) {}
   *
   *        public async hashPassword(data: { password: string; email: string }) {
   *            // your logic above
   *            const salt = this.hasherService.genSalt(10)
   *            const hashedPassw = await this.hasherService.hash(data.password, salt)
   *            }
   *    }
   */
  public async hash(data: string, salt?: string | number): Promise<string> {
    const _salt = salt ?? this.salt ?? bcrypt.genSaltSync(10);
    return bcrypt.hash(data, _salt);
  }

  /**
   *
   * @param data The data to be encrypted.
   * @param salt to be used to hash the data. if not set would use the salt set from the HasherModule's register function
   * @returns A promise to be either resolved with the encrypted data salt or rejected with an Error
   * @example export class AuthenticationService {
   *        constructor(private readonly hasherService: HasherService) {}
   *
   *        public hashPassword(data: { password: string; email: string }) {
   *            // your logic above
   *            const salt = this.hasherService.genSaltSync(10)
   *            const hashedPassw = this.hasherService.hashSync(data.password, salt)
   *            }
   *    }
   */
  public hashSync(data: string, salt?: string | number): string {
    const _salt = salt ?? this.salt ?? bcrypt.genSaltSync(10);
    return bcrypt.hashSync(data, _salt);
  }

  /**
   *
   * @param hash the encrypted hash
   * @returns
   */
  public getRounds(hash: string): number {
    return bcrypt.getRounds(hash);
  }

  /**
   *
   * @param rounds The cost of processing the data. Default 10.
   * @param minor The minor version of bcrypt to use. Either 'a' or 'b'. Default 'b'.
   * @returns  A promise to be either resolved with the generated salt or rejected with an Error
   *
   * @example export class AuthenticationService {
   *        constructor(private readonly hasherService: HasherService) {}
   *
   *        public async hashPassword(data: { password: string; email: string }) {
   *            // your logic above
   *            const salt = await this.hasherService.genSalt(10)
   *            }
   *    }
   */
  public async genSalt(rounds: number, minor?: 'a' | 'b') {
    return bcrypt.genSalt(rounds, minor);
  }

  /**
   *
   * @param rounds The cost of processing the data. Default 10.
   * @param minor The minor version of bcrypt to use. Either 'a' or 'b'. Default 'b'.
   * @returns  A promise to be either resolved with the generated salt or rejected with an Error
   *
   * @example export class AuthenticationService {
   *        constructor(private readonly hasherService: HasherService) {}
   *
   *        public genSaltSync(data: { password: string; email: string }) {
   *            // your logic above
   *            const salt = this.hasherService.genSaltSync(10)
   *            }
   *    }
   */
  public genSaltSync(rounds: number, minor?: 'a' | 'b') {
    return bcrypt.genSaltSync(rounds, minor);
  }
}
