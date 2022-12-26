export type BcryptSalt = string | number;

export interface BcryptModuleOptions {
  salt: BcryptSalt;
}
