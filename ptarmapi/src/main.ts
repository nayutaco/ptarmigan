import { NestFactory } from '@nestjs/core';
import { SwaggerModule, DocumentBuilder, SwaggerBaseConfig } from '@nestjs/swagger';
import { AppModule } from './app.module';
import { Logger } from '@nestjs/common';
import { ConfigService } from 'nestjs-config';
import { NestExpressApplication } from '@nestjs/platform-express';
import { WsAdapter } from '@nestjs/platform-ws';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  app.useWebSocketAdapter(new WsAdapter(app));

  // swagger setting
  const options = new DocumentBuilder()
    .setTitle('ptarmigan REST-API')
    .setDescription('Lightning Network implementation ptarmigan REST-API')
    .addBearerAuth('Authorization', 'header')
    .setVersion('0.2')
    .build();
  const document = SwaggerModule.createDocument(app, options);
  SwaggerModule.setup('api', app, document);

  const config = ConfigService;
  Logger.log('ptarmdRpcPort: ' + config.get('ptarmigan.ptarmdRpcPort'));
  Logger.log('ptarmdHost: + ' + config.get('ptarmigan.ptarmdHost'));
  Logger.log('bitcoindRpcPort: ' + config.get('ptarmigan.bitcoindRpcPort'));
  Logger.log('bitcoindHost: ' + config.get('ptarmigan.bitcoindHost'));
  Logger.log('bitcoindHost: ' + config.get('ptarmigan.apiToken'));

  await app.listen(3000);
}
bootstrap();
