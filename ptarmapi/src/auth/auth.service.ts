import { Injectable } from '@nestjs/common';
import { ConfigService } from 'nestjs-config';

@Injectable()
export class AuthService {

  constructor() { }

  async validateApiToken(token: string): Promise<any> {
    const apiToken = ConfigService.get('ptarmigan.apiToken');
    if (token === apiToken) {
      return true;
    }
    return false;
  }
}
