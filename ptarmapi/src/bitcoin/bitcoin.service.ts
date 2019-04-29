import { Injectable } from '@nestjs/common';
import { exec, execSync } from 'child_process';
import { ConfigService } from 'nestjs-config';
import * as rp from 'request-promise';
import * as jayson from 'jayson/promise';
import { Logger } from '@nestjs/common';

@Injectable()
export class BitcoinService {
    private port: number;
    private host: string;
    private username: string;
    private password: string;
    private client: jayson.Client;

    constructor(
        private readonly config: ConfigService,
    ) {
        this.config = config;
        this.port = Number.parseInt(this.config.get('ptarmigan.bitcoindRpcPort'), 10),
        this.host = this.config.get('ptarmigan.bitcoindHost'),
        this.username = this.config.get('ptarmigan.bitcoindUser'),
        this.password = this.config.get('ptarmigan.bitcoindPassword'),
        this.client = jayson.Client.http({
            port: this.port,
            host: this.host,
            auth: this.username + ':' + this.password,
        });
    }

    async requestHTTP(method, params): Promise<string> {
        const req = this.client.request(method, params);
        Logger.log(this.client);
        Logger.log(method);
        Logger.log(params);

        const options = {
            method,
            headers: {
                'content-type': 'text/plain',
            },
        };
        params.push();
        Logger.log(params);

        return Promise.resolve(req)
        .then((res) => {
            Logger.log(res);
            return res;
        })
        .catch((err) => {
            Logger.log(err);
            return err;
        });
    }
}
