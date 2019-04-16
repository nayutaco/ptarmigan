import { Test, TestingModule } from '@nestjs/testing';
import { PtarmiganController } from './ptarmigan.controller';

describe('Ptarmigan Controller', () => {
  let controller: PtarmiganController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [PtarmiganController],
    }).compile();

    controller = module.get<PtarmiganController>(PtarmiganController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
