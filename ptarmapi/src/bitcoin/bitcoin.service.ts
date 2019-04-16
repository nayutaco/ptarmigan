import { Injectable } from '@nestjs/common';
import { exec, execSync } from 'child_process';
import { ConfigService } from 'nestjs-config';
import * as rp from 'request-promise';
import * as jayson from 'jayson/promise';
import { Logger } from '@nestjs/common';

@Injectable()
export class BitcoinService {
    private port: number
    private host: string
    private username: string
    private password: string
    private client: jayson.Client;

    constructor(
        private readonly config: ConfigService,
    ) {
        this.config = config;
        this.port = Number.parseInt(this.config.get('ptarmigan.bitcoindPort')),
        this.host = this.config.get('ptarmigan.bitcoindHost'),
        this.username = this.config.get('ptarmigan.bitcoindUser'),
        this.password = this.config.get('ptarmigan.bitcoindPassword')

        this.client = jayson.Client.http({
            port: this.port,
            host: this.host,
            auth: this.username + ':' + this.password
        });
    }

    async requestHTTP(method, params): Promise<string> {
        let req = this.client.request(method, params)
        // bash-3.2$ curl --data-binary '{"jsonrpc":"1.0","id":"curltext","method":"getwalletinfo","params":[]}' 
        // -H 'content-type:text/plain;' http://bitcoinuser:bitcoinpassword@127.0.0.1:18332
        // {"result":{"walletname":"","walletversion":169900,"balance":0.00000000,"unconfirmed_balance":0.00000000,"immature_balance":0.00000000,"txcount":0,"keypoololdest":1554805640,"keypoolsize":1000,"keypoolsize_hd_internal":1000,"paytxfee":0.00000000,"hdseedid":"cad3069a2301fdc384f220d22daf4e1c7b906608","private_keys_enabled":true},"error":null,"id":"curltext"}
        Logger.log(this.client)
        Logger.log(method)
        Logger.log(params)

        let options = {
            method: method,
            headers: {
                'content-type': 'text/plain'
            }
        }
        params.push()
        Logger.log(params)

        return Promise.resolve(req)
        .then((res) => {
            Logger.log(res)
            return res
        })
        .catch((err) => {
            Logger.log(err)
            return err
        })
    }
}
