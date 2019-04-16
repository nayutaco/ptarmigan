import { Test, TestingModule } from '@nestjs/testing';
import { BitcoinService } from './bitcoin.service';

describe('BitcoinService', () => {
  let service: BitcoinService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [BitcoinService],
    }).compile();

    service = module.get<BitcoinService>(BitcoinService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
