import { Injectable } from '@nestjs/common';
import { exec, execSync } from 'child_process';
import { ConfigService } from 'nestjs-config';
import * as rp from 'request-promise';
import * as jayson from 'jayson/promise';
import { Logger } from '@nestjs/common';

@Injectable()
export class PtarmiganService {
    private port: number
    private host: string
    private client: jayson.Client
    private path: string

    constructor(
        private readonly config: ConfigService,
    ) {
        this.config = config;
        this.port = Number.parseInt(this.config.get('ptarmigan.ptarmdPort')),
        this.host = this.config.get('ptarmigan.ptarmdHost')
        this.path = this.config.get('ptarmigan.ptarmdPath')
        this.client = jayson.Client.tcp({
            port: this.port,
            host: this.host
        })
    }

    async requestTCP(method, params): Promise<string> {
        let req = this.client.request(method, params)

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

    commandExecuteSync(command: string, params: Array<string>): Buffer {
        Logger.log('commandExecuteSync')

        let param = ''
        params.forEach(s => {
            param = param + ' ' + s
        })
        // const p2: string = params.reduce((s, p) => s + ' ' + p, 0)

        Logger.log(params)
        Logger.log(param)
        return execSync(this.path + '/' + command + '' + param, {timeout: 3000})
    }

    async commandExecute(command: string): Promise<string> {
        Logger.log('commandExecute')
        return new Promise((resolve, reject) => {
            exec(this.path + '/' + command, {timeout: 3000}), (error, stdout, stderr) => {
                Logger.log(error, stdout, stderr)
                if (error) resolve(error)
                if (stderr) resolve(stderr)
                resolve(stdout)
            }
        })
    }
}
