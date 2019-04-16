import { Test, TestingModule } from '@nestjs/testing';
import { PtarmiganService } from './ptarmigan.service';

describe('PtarmiganService', () => {
  let service: PtarmiganService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [PtarmiganService],
    }).compile();

    service = module.get<PtarmiganService>(PtarmiganService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
