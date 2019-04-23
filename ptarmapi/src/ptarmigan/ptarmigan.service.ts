import { Injectable } from '@nestjs/common'
import { exec, execSync } from 'child_process'
import { ConfigService } from 'nestjs-config'
import * as rp from 'request-promise'
import * as jayson from 'jayson/promise'
import { Logger } from '@nestjs/common'
import * as fs from 'fs'
import * as dotenv from 'dotenv'

@Injectable()
export class PtarmiganService {
    private port: number
    private host: string
    private client: jayson.Client
    private path: string
    private nodePath: string

    constructor(
        private readonly config: ConfigService,
    ) {
        this.config = config;
        this.port = Number.parseInt(this.config.get('ptarmigan.ptarmdPort')),
        this.host = this.config.get('ptarmigan.ptarmdHost')
        this.path = this.config.get('ptarmigan.ptarmdPath')
        this.nodePath = this.config.get('ptarmigan.ptarmdNodePath')
        this.client = jayson.Client.tcp({
            port: this.port,
            host: this.host
        })
    }

    async requestTCP(method, params): Promise<string> {
        let req = this.client.request(method, params)
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

    commandExecute(command: string, params: Array<string>): Buffer {
        let param = ''
        params.forEach(s => {
            param = param + ' ' + s
        })
        // const p2: string = params.reduce((s, p) => s + ' ' + p, 0)
        Logger.log(params)
        Logger.log(param)
        return execSync(this.path + '/' + command + '' + param, {timeout: 30000})
    }

    commandExecuteShowdbGetChannels(): Buffer {
        return execSync(this.path + '/showdb' + ' --datadir ' + this.nodePath + ' -c ', {timeout: 30000})
    }

    commandExecuteShowdbListGossipNode(): Buffer {
        return execSync(this.path + '/showdb' + ' --datadir ' + this.nodePath + ' -n ', {timeout: 30000})
    }

    commandExecuteRoutingGetRoute(senderNodeId: string, receiverNodeId: string): Buffer {
        return execSync(this.path + '/routing' + ' -d ' + this.nodePath + ' -s ' + senderNodeId + ' -r ' + receiverNodeId, {timeout: 30000})
    }

    commandExecutePayFundin(fundingSat, pushMsat, outputFileName): Buffer {
        return execSync('python3' + ' ' + this.path + '/pay_fundin.py' + ' ' + fundingSat + ' ' + pushMsat + ' ' + outputFileName, {timeout: 30000})
    }

    async commandExecuteOpenChannel(peerNodeId: string, fundingSat: number, pushMsat: number, feeratePerKw: number): Promise<string> {
        let utime = new Date().getTime() / 1000
        let filename = utime.toString() + '.txt'
        try {
            let res = this.commandExecutePayFundin(fundingSat, pushMsat, filename)
            let content = dotenv.parse(fs.readFileSync(filename + ''))
            let txId = content['txid']
            let txIndex = content['txindex']
            return await this.requestTCP("fund", [peerNodeId, '0.0.0.0', 0, txId, txIndex, feeratePerKw])
        } catch (error) {
            Logger.log(error)
            if (error.status == 1) {
                // ERR_INVALID_ARG
                return error.stderr.toString()
            } else if (error.status == 2) {
                // ERR_NO_AMOUNT
                return error.stderr.toString()
            } else if (error.status == 3) {
                // ERR_BC_CREATE_TX
                return error.stderr.toString()
            } else if (error.status == 4) {
                // ERR_BC_SEND_TX
                return error.stderr.toString()
            } else if (error.status == 100) {
                // ERR_EXCEPTION
                return error.stderr.toString()
            } else if (error.code == 'ENOENT'){
                return 'File not found'
            }
        }
    }
}
