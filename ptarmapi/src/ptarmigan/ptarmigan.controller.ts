import { Controller, Get, Patch, Put, Param, Post, Body, Delete, Logger, Query } from '@nestjs/common';
import { exec, execSync } from 'child_process';
import { PtarmiganService } from './ptarmigan.service';
import { BitcoinService } from '../bitcoin/bitcoin.service';
import { ApiUseTags, ApiModelProperty, ApiImplicitQuery, ApiCreatedResponse, ApiForbiddenResponse } from '@nestjs/swagger';
import { Validate, Matches } from 'class-validator';

export class FeeDto {
    @ApiModelProperty(
        {
            required: true,
            description: 'feerate per kw',
        },
    )
    feeratePerKw: number;
}

export class PaymentHashDto {
    @ApiModelProperty(
        {
            required: true,
            description: "payment hash"
        }
    )
    paymentHash: string
}

export class Bolt11Dto {
    @ApiModelProperty(
        {
            required: true,
            description: "bolt11 invoice"
        }
    )
    bolt11: string
}

export class InvoiceDto {
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
            required: true,
            default: 9735
        }
    )
    peerPort: number
}

export class PeerNodeDto {
    @ApiModelProperty(
        {
            required: true,
        }
    )
    peerNodeId: string
}

export class FundDto {
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
    fundingSat: number

    @ApiModelProperty(
        {
            required: true
        }
    )
    pushMsat: number

    @ApiModelProperty(
        {
            required: false,
            default: 0
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

export class RouteNodeDto {
    @ApiModelProperty(
        {
            required: true,
            pattern: "^[0-9a-fA-F]."
        }
    )
    senderNodeId: string
    @ApiModelProperty(
        {
            required: true,
            pattern: "^[0-9a-fA-F]."
        }
    )
    receiverNodeId: string
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
    @ApiCreatedResponse({ description: 'The record has been successfully created.' })
    @ApiForbiddenResponse({ description: 'Forbidden.' })
    async executeGetInfo(): Promise<string> {
        return await this.ptarmiganService.requestTCP("getinfo", {});
    }

    @Post('setfeerate') // setfeerate -> setfeerate
    async executeSetFeerate(@Body() dto: FeeDto) {
        //return await this.ptarmiganService.requestTCP("setfeerate", [feeratePerKw]);
        return await this.ptarmiganService.requestTCP("setfeerate", [dto.feeratePerKw])
    }

    @Post('estimatefundingfee') // estimatefundingfee -> dev-estimatefundingfee
    async executeEstimateFundingFee(@Body() dto: FeeDto) {
        return await this.ptarmiganService.requestTCP("estimatefundingfee", [dto.feeratePerKw])
    }

    // TODO: [100], 100レスポンス確認
    /*
    @Post('estimatefundingfee/:feeratePerKw') // estimatefundingfee -> dev-estimatefundingfee
    async executeEstimateFundingFee( @Param('feeratePerKw') feeratePerKw: number) {
        Logger.log(feeratePerKw)
        Logger.log(typeof feeratePerKw)
        return await this.ptarmiganService.requestTCP("estimatefundingfee", [ feeratePerKw ])
    }
    */

    @Post('createinvoice') // createinvoice -> invoice
    async executeCreateInvoice(@Body() dto: InvoiceDto) {
        return await this.ptarmiganService.requestTCP("invoice", [dto.amountMsat, dto.minFinalCltvExpiry])
    }

    @Post('removeinvoice') // eraseinvoice -> removeinvoice
    async executeEraseInvoice(@Body() dto: PaymentHashDto) {
        return await this.ptarmiganService.requestTCP("eraseinvoice", [dto.paymentHash])
    }

    @Post('removeallinvoices') // eraseinvoice -> removeallinvoices
    async executeRemoveAllInvoices() {
        return await this.ptarmiganService.requestTCP("eraseinvoice", ['ALL'])
    }

    @Post('listinvoices') // listinvoice -> listinvoices
    async executeListInvoice() {
        return await this.ptarmiganService.requestTCP("listinvoice", [])
    }

    @Post('decodeinvoice') // none -> decodeinvoice
    async executeDecodeInvoice(@Body() dto: Bolt11Dto) {
        return await this.ptarmiganService.requestTCP("decodeinvoice", [dto.bolt11])
    }

    // ------------------------------------------------------------------------------
    // peer
    // ------------------------------------------------------------------------------
    @Post('connect') // connect -> connectpeer
    async executeConnect(@Body() dto: PeerDto) {
        return await this.ptarmiganService.requestTCP("connect", [dto.peerNodeId, dto.peerAddr, dto.peerPort])
    }

    @Post('disconnect') // disconnect -> disconnectpeer
    async executeDisconnect(@Body() dto: PeerNodeDto) {
        return await this.ptarmiganService.requestTCP("disconnect", [dto.peerNodeId, '0.0.0.0', 0])
    }

    @Post('getlasterror') // getlasterror -> getlasterror
    async executeGetLastErrort(@Body() dto: PeerNodeDto) {
        return await this.ptarmiganService.requestTCP("getlasterror", [dto.peerNodeId, '0.0.0.0', 0])
    }

    @Post('dev-disautoconn') // disautoconn -> dev-disableautoconnect
    @ApiImplicitQuery({
        name: 'enable',
        enum: [0, 1]
    })
    async executeDisAutoConn(@Query('enable') enable: number) {
        return await this.ptarmiganService.requestTCP("disautoconn", [enable.toString(10)])
    }

    @Post('dev-listtransactions') // getcommittx -> dev-listtransactions
    async executeGetCommitTx(@Body() dto: PeerNodeDto) {
        return await this.ptarmiganService.requestTCP("getcommittx", [dto.peerNodeId, '0.0.0.0', 0])
    }

    // ------------------------------------------------------------------------------
    // channel
    // ------------------------------------------------------------------------------
    @Post('openchannel') // fund -> openchannel
    async executeOpenChannel(@Body() dto: FundDto) {
        return await this.ptarmiganService.commandExecuteOpenChannel(dto.peerNodeId, dto.fundingSat, dto.pushMsat, dto.feeratePerKw)
    }

    @Post('close') // close -> closechannel
    async executeAddInvoice(@Body() dto: PeerNodeDto) {
        return await this.ptarmiganService.requestTCP("close", [dto.peerNodeId, '0.0.0.0', 0])
    }

    @Post('dev-removechannel/:channelId') // removechannel -> dev-removechannel
    async executeRemoveChannel(@Param('channelId') channelId: string) {
        return await this.ptarmiganService.requestTCP("removechannel", [channelId])
    }

    @Post('resetroutestate') // removechannel -> dev-removechannel
    async executeResetRouteState() {
        return await this.ptarmiganService.requestTCP("resetroutestate", [])
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
    async executeListUnspent(@Body() dto: ListUnspentDto): Promise<string> {
        return await this.bitcoinService.requestHTTP("listunspent", [dto.minconf, dto.maxconf, dto.addresses]);
    }

    @Post('listchannels')
    async executeListChannels(): Promise<string> {
        try {
            return this.ptarmiganService.commandExecuteShowdbGetChannels().toString();
        } catch (error) {
            return "error";
        }
    }

    @Post('listnodes')
    async executeListNodes(): Promise<string> {
        try {
            return this.ptarmiganService.commandExecuteShowdbListGossipNode().toString();
        } catch (error) {
            return "error";
        }
    }

    @Post('getroute')
    async executeGetRoute(@Body() dto: RouteNodeDto): Promise<string> {
        try {
            return this.ptarmiganService.commandExecuteRoutingGetRoute(dto.senderNodeId, dto.receiverNodeId).toString();
        } catch(error) {
            return "error";
        }
    }
}
