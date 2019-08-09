import { Injectable } from '@nestjs/common';
import { Logger } from '@nestjs/common';
import { AddFinalDto } from 'src/model/addfinal';
import * as LRU from "lru-cache";

@Injectable()
export class CacheService {

    private cache = new LRU();
    private logger = new Logger('CacheService');

    constructor() { }

    async onModuleInit() {
        this.cache.reset();
    }

    public write(addFinal: AddFinalDto): boolean {
        try {
            return this.cache.set(Math.random().toString(36).slice(-10), addFinal.paymentHash, 3600000)
        } catch (error) {
            this.logger.log(error);
        }
    }

    public delete(key: string): boolean {
        try {
            return this.cache.del(key);
        } catch (error) {
            this.logger.log(error);
        }
    }

    public getPaymentHashs(): AddFinalDto[] {
        try {
            const hashes: AddFinalDto[] = [];
            this.cache.forEach((value, key) => {
                hashes.push({
                    id: key,
                    paymentHash: value
                });
            });
            return hashes;
        } catch (error) {
            this.logger.log(error);
        }
    }

}
