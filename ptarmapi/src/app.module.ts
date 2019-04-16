import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PtarmiganService } from './ptarmigan/ptarmigan.service';
import { PtarmiganController } from './ptarmigan/ptarmigan.controller';
import { ConfigModule } from 'nestjs-config';
import { BitcoinService } from './bitcoin/bitcoin.service';
import * as path from 'path';

@Module({
  controllers: [AppController, PtarmiganController],
  providers: [AppService, PtarmiganService, BitcoinService],
  imports: [
    ConfigModule.load(path.resolve(__dirname, 'config', '**/!(*.d).{ts,js}')),
    AppModule
  ],
})
export class AppModule {}
