import { Controller, Get, Patch, Put, Param, Post, Body, Delete } from '@nestjs/common';
import { exec, execSync } from 'child_process';
import { PtarmiganService } from './ptarmigan.service';
import { BitcoinService } from '../bitcoin/bitcoin.service';
import { ApiUseTags, ApiModelProperty, ApiImplicitQuery } from '@nestjs/swagger';

export class AddInvoiceDto {
    @ApiModelProperty(
        {
            required: true,
            description: "amount msatoshi"
        }
    )
    amountMsat: number

    @ApiModelProperty(
        {
            required: false
        }
    )
    minFinalCltvExpiry?: number
}

export class PeerDto {
    @ApiModelProperty(
        {
            required: true,
        }
    )
    peerNodeId: string

    @ApiModelProperty(
        {
            required: true
        }
    )
    peerAddr: string

    @ApiModelProperty(
        {
            required: true
        }
    )
    peerPort: number    
}

export class FundDto {
    @ApiModelProperty(
        {
            required: true
        }
    )
    txId: string
    @ApiModelProperty(
        {
            required: true
        }
    )
    txIndex: number
    @ApiModelProperty(
        {
            required: true
        }
    )
    fundingSat: number
    @ApiModelProperty(
        {
            required: true
        }
    )
    pushSat: number
    @ApiModelProperty(
        {
            required: true
        }
    )
    feeratePerKw: number
}

export class ListUnspentDto {
    @ApiModelProperty(
        {
            required: true,
            default: 1,
            minimum: 0,
            maximum: 9999999,
        }
    )
    minconf: number

    @ApiModelProperty(
        {
            required: true,
            default: 9999999,
            minimum: 0,
            maximum: 9999999,
        }
    )    
    maxconf: number

    @ApiModelProperty(
        {
            type: [String],
            required: false,
            default: []
        }
    )
    addresses: string[]
}

@ApiUseTags('ptarmigan')
@Controller('/')
export class PtarmiganController {

    constructor(
        private readonly ptarmiganService: PtarmiganService,
        private readonly bitcoinService: BitcoinService
    ) {
    }

    /*
    @Get('help') // none -> help
    async executeHelp() {
        return await this.ptarmiganService.requestTCP("help", []);
    }
    */

    @Post('stop') // stop -> stop
    async executeStop() {        
        return await this.ptarmiganService.requestTCP("stop", []);
    }

    @Post('getinfo') // getinfo -> getinfo
    async executeGetInfo(): Promise<string> {
        return await this.ptarmiganService.requestTCP("getinfo", {});
    }

    @Post('setfeerate/:feeratePerKw') // setfeerate -> setfeerate
    async executeSetFeerate( @Param('feeratePerKw') feeratePerKw: number ) {
        return await this.ptarmiganService.requestTCP("setfeerate", [feeratePerKw]);
    }

    @Post('estimatefundingfee/:feeratePerKw') // estimatefundingfee -> dev-estimatefundingfee
    async executeEstimateFundingFee( @Param('feeratePerKw') feeratePerKw: number ) {
        return await this.ptarmiganService.requestTCP("estimatefundingfee", [feeratePerKw]);
    }

    @Post('eraseinvoice/:paymentHash') // eraseinvoice -> removeinvoice
    async executeEraseInvoice( @Param('paymentHash') paymentHash?: string ) {
        return await this.ptarmiganService.requestTCP("eraseinvoice", [paymentHash]);
    }    

    /*
    @Delete('removeallinvoices') // eraseinvoice -> removeallinvoices
    async executeRemoveAllInvoices() {
        return await this.ptarmiganService.requestTCP("removeallinvoices", []);
    }
    */   

   @Post('listinvoice') // listinvoice -> listinvoices
   async executeListInvoice() {
       return await this.ptarmiganService.requestTCP("listinvoice", []);
   }

    /*
    @Get('decodeinvoice/:bolt11') // none -> decodeinvoice
    async executeDecodeInvoice( @Param('bolt11') bolt11: string ) {
        return await this.ptarmiganService.requestTCP("decodeinvoice", [bolt11]);
    }
    */

    // ------------------------------------------------------------------------------
    // peer
    // ------------------------------------------------------------------------------
    @Post('connect') // connect -> connectpeer
    async executeConnect( @Body() dto: PeerDto ) {
        return await this.ptarmiganService.requestTCP("connect", [dto.peerNodeId, dto.peerAddr, dto.peerPort])
    }  

    @Post('disconnect') // disconnect -> disconnectpeer
    async executeDisconnect( @Body() dto: PeerDto ) {
        return await this.ptarmiganService.requestTCP("disconnect", [dto.peerNodeId, dto.peerAddr, dto.peerPort])
    }  

    @Post('getlasterror') // getlasterror -> getlasterror
    async executeGetLastErrort( @Body() dto: PeerDto ) {
        return await this.ptarmiganService.requestTCP("getlasterror", [dto.peerNodeId, dto.peerAddr, dto.peerPort])
    }      

    @ApiImplicitQuery({ name: 'disable', enum: [0, 1]})
    @Post('disautoconn') // disautoconn -> dev-disableautoconnect
    async executeDisAutoConn( @Param('disable') disable: number ) {
        return await this.ptarmiganService.requestTCP("disautoconn", disable)
    }

    @Post('getcommittx') // getcommittx -> dev-listtransactions
    async executeGetCommitTx( @Body() dto: PeerDto ) {
        return await this.ptarmiganService.requestTCP("getcommittx", [dto.peerNodeId, dto.peerAddr, dto.peerPort])
    }

    // ------------------------------------------------------------------------------
    // channel
    // ------------------------------------------------------------------------------
    // TODO: add to pay_fundin.py to openchannel 
    @Post('fund') // fund -> openchannel
    async executeFund( @Body() peerDto: PeerDto, fundDto: FundDto) {
        //let fundingSat: number = 10000
        //let pushMsat: number   = 10000
        //this.ptarmiganService.commandExecuteSync("pay_fundin.py", [fundingSat, pushMsat]).toString()
        return await this.ptarmiganService.requestTCP("fund", [peerDto.peerNodeId, peerDto.peerAddr, peerDto.peerPort, fundDto.txId, fundDto.txIndex, fundDto.fundingSat, fundDto.pushSat, fundDto.feeratePerKw])
    }

    @Post('close') // close -> closechannel
    async executeAddInvoice( @Body() dto: PeerDto) {
        return await this.ptarmiganService.requestTCP("close", [dto.peerNodeId, dto.peerAddr, dto.peerPort])
    }

    @Post('removechannel') // removechannel -> dev-removechannel
    async executeRemoveChannel( @Param('channelId') channelId: string) {
        return await this.ptarmiganService.requestTCP("removechannel", [channelId])
    }

    // ------------------------------------------------------------------------------
    // fund
    // ------------------------------------------------------------------------------
    @Post('getwalletinfo') // getnewaddress
    async executeGetWalletInfo(): Promise<string> {
        return await this.bitcoinService.requestHTTP("getwalletinfo", []);
    }
    
    @Post('getnewaddress') // getnewaddress
    async executeGetNewAddress(): Promise<string> {
        return await this.bitcoinService.requestHTTP("getnewaddress", ["", "p2sh-segwit"]);
    }

    @Post('listunspent') // listunspent
    async executeListUnspent( @Body() dto: ListUnspentDto): Promise<string> {
        return await this.bitcoinService.requestHTTP("listunspent", [dto.minconf, dto.maxconf, dto.addresses]);
    }

    @Post('getchannels')
    async executeGetChannelsSync(): Promise<string> {
        return this.ptarmiganService.commandExecuteSync("showdb", ["-l"]).toString()
    }

    @Post('getchannels')
    async executeGetChannels(): Promise<string> {
        return this.ptarmiganService.commandExecuteSync("showdb", ["-l"]).toString()
    }

    // TODO: getroute add DTO parameter
    @Post('getroute')
    async executeGetRoute(): Promise<string> {
        return this.ptarmiganService.commandExecuteSync("routing", ["-s" + " xxx", "-r" + " yyy"]).toString()
    }
}
