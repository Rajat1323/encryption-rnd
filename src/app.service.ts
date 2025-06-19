import { Injectable } from '@nestjs/common';
import { decryptObject, encryptObject } from './utils/crypto-util';

@Injectable()
export class AppService {
  getEncript(encript: any) {
    return encryptObject(encript);
  }

  makeDecript(encrypted: any) {
    return decryptObject(encrypted);
  }
}
