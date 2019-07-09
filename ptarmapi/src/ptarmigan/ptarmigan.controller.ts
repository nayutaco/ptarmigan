import { Controller, Get, Patch, Put, Param, Post, Body, Delete, Logger, Query, Next } from '@nestjs/common';
import { exec, execSync } from 'child_process';
import { PtarmiganService } from './ptarmigan.service';
import { BitcoinService } from '../bitcoin/bitcoin.service';
import { ApiUseTags, ApiModelProperty, ApiImplicitQuery, ApiCreatedResponse, ApiForbiddenResponse } from '@nestjs/swagger';
import { Validate, Matches } from 'class-validator';
import { FeeDto } from 'src/model/fee';
import { InvoiceDto } from 'src/model/invoice';
import { ListInvoiceDto } from 'src/model/list-invoice';
import { PaymentHashDto } from 'src/model/payment-hash';
import { Bolt11Dto } from 'src/model/bolt11';
import { PeerDto } from 'src/model/peer';
import { PeerNodeDto } from 'src/model/peer-node';
import { FundDto } from 'src/model/fund';
import { ListUnspentDto } from 'src/model/list-unspent';
import { RouteNodeDto } from 'src/model/route-node';
import { PaymentIdDto } from 'src/model/payment-id';
import { SendPaymentDto } from 'src/model/send-payment';
import { ListPaymentDto } from 'src/model/list-payment';
import { AddFinalDto } from 'src/model/addfinal';
import { ListInvoiceResponseDto } from 'src/model/list-invoice-response';
import { CacheService } from '../cache/cache.servies'
import { InvoicesGateway } from '../notifications/invoices.gateway';

@ApiUseTags('ptarmigan')
@Controller('/')
export class PtarmiganController {

    constructor(
        private readonly ptarmiganService: PtarmiganService,
        private readonly bitcoinService: BitcoinService,
        private readonly cacheService: CacheService,
        private readonly invoicesGateway: InvoicesGateway
    ) {
    }

    @Post('stop') // stop -> stop
    async executeStop() {
        return await this.ptarmiganService.requestTCP('stop', []);
    }

    @Post('getinfo') // getinfo -> getinfo
    async executeGetInfo(): Promise<string> {
        return await this.ptarmiganService.requestTCP('getinfo', []);
    }

    @Post('setfeerate') // setfeerate -> setfeerate
    async executeSetFeerate(@Body() dto: FeeDto) {
        return await this.ptarmiganService.requestTCP('setfeerate', [dto.feeratePerKw]);
    }

    @Post('estimatefundingfee') // estimatefundingfee -> dev-estimatefundingfee
    async executeEstimateFundingFee(@Body() dto: FeeDto) {
        return await this.ptarmiganService.requestTCP('estimatefundingfee', [dto.feeratePerKw]);
    }

    @Post('createinvoice') // createinvoice -> invoice
    async executeCreateInvoice(@Body() dto: InvoiceDto) {
        return await this.ptarmiganService.requestTCP('invoice', [dto.amountMsat, dto.minFinalCltvExpiry, dto.description, dto.invoiceExpiry]);
    }

    @Post('removeinvoice') // eraseinvoice -> removeinvoice
    async executeEraseInvoice(@Body() dto: PaymentHashDto) {
        return await this.ptarmiganService.requestTCP('eraseinvoice', [dto.paymentHash]);
    }

    @Post('removeallinvoices') // eraseinvoice -> removeallinvoices
    async executeRemoveAllInvoices() {
        return await this.ptarmiganService.requestTCP('eraseinvoice', ['']);
    }

    @Post('listinvoices') // listinvoice -> listinvoices
    async executeListInvoice(@Body() dto: ListInvoiceDto) {
        return await this.ptarmiganService.requestTCP('listinvoice', [dto.paymentHash]);
    }

    @Post('decodeinvoice') // none -> decodeinvoice
    async executeDecodeInvoice(@Body() dto: Bolt11Dto) {
        return await this.ptarmiganService.requestTCP('decodeinvoice', [dto.bolt11]);
    }

    // ------------------------------------------------------------------------------
    // peer
    // ------------------------------------------------------------------------------
    @Post('connect') // connect -> connectpeer
    async executeConnect(@Body() dto: PeerDto) {
        return await this.ptarmiganService.requestTCP('connect', [dto.peerNodeId, dto.peerAddr, dto.peerPort]);
    }

    @Post('disconnect') // disconnect -> disconnectpeer
    async executeDisconnect(@Body() dto: PeerNodeDto) {
        return await this.ptarmiganService.requestTCP('disconnect', [dto.peerNodeId, '0.0.0.0', 0]);
    }

    @Post('getlasterror') // getlasterror -> getlasterror
    async executeGetLastErrort(@Body() dto: PeerNodeDto) {
        return await this.ptarmiganService.requestTCP('getlasterror', [dto.peerNodeId, '0.0.0.0', 0]);
    }

    @Post('dev-disautoconn') // disautoconn -> dev-disableautoconnect
    @ApiImplicitQuery({
        name: 'enable',
        enum: [0, 1],
    })
    async executeDisAutoConn(@Query('enable') enable: number) {
        return await this.ptarmiganService.requestTCP('disautoconn', [enable.toString(10)]);
    }

    @Post('dev-listtransactions') // getcommittx -> dev-listtransactions
    async executeGetCommitTx(@Body() dto: PeerNodeDto) {
        return await this.ptarmiganService.requestTCP('getcommittx', [dto.peerNodeId, '0.0.0.0', 0]);
    }

    // ------------------------------------------------------------------------------
    // channel
    // ------------------------------------------------------------------------------
    @Post('openchannel') // fund -> openchannel
    async executeOpenChannel(@Body() dto: FundDto) {
        return await this.ptarmiganService.commandExecuteOpenChannel(dto.peerNodeId, dto.fundingSat, dto.pushMsat, dto.feeratePerKw);
    }

    @Post('close') // close -> closechannel
    async executeCloseChannel(@Body() dto: PeerNodeDto) {
        return await this.ptarmiganService.requestTCP('close', [dto.peerNodeId, '0.0.0.0', 0]);
    }

    @Post('forceclose') // close -> closechannel
    async executeForceCloseChannel(@Body() dto: PeerNodeDto) {
        return await this.ptarmiganService.requestTCP('close', [dto.peerNodeId, '0.0.0.0', 0, 'force']);
    }

    @Post('dev-removechannel/:channelId') // removechannel -> dev-removechannel
    async executeRemoveChannel(@Param('channelId') channelId: string) {
        return await this.ptarmiganService.requestTCP('removechannel', [channelId]);
    }

    @Post('resetroutestate') // removechannel -> dev-removechannel
    async executeResetRouteState() {
        return await this.ptarmiganService.requestTCP('resetroutestate', []);
    }

    // ------------------------------------------------------------------------------
    // payment
    // ------------------------------------------------------------------------------
    @Post('sendpayment') // routepay -> sendpayment
    async executeSendPayment(@Body() dto: SendPaymentDto) {
        return await this.ptarmiganService.requestTCP('routepay', [dto.bolt11, dto.addAmountMsat]);
    }

    @Post('listpayments') // listpayment -> listpayments
    async executeListPaymentsState() {
        return await this.ptarmiganService.requestTCP('listpayment', []);
    }

    @Post('listpayment') // listpayment -> listpayment=0
    async executeListPaymentState(@Body() dto: ListPaymentDto) {
        return await this.ptarmiganService.requestTCP('listpayment', [dto.listpayment]);
    }

    @Post('removepayment') // removepayment -> removepayment
    async executeRemovePaymentState(@Body() dto: PaymentIdDto) {
        return await this.ptarmiganService.requestTCP('removepayment', [dto.paymentId]);
    }

    // ------------------------------------------------------------------------------
    // fund
    // ------------------------------------------------------------------------------
    @Post('getwalletinfo') // getnewaddress
    async executeGetWalletInfo(): Promise<string> {
        return await this.bitcoinService.requestHTTP('getwalletinfo', []);
    }

    @Post('getnewaddress') // getnewaddress
    async executeGetNewAddress(): Promise<string> {
        return await this.bitcoinService.requestHTTP('getnewaddress', ['', 'p2sh-segwit']);
    }

    @Post('listunspent') // listunspent
    async executeListUnspent(@Body() dto: ListUnspentDto): Promise<string> {
        return await this.bitcoinService.requestHTTP('listunspent', [dto.minconf, dto.maxconf, dto.addresses]);
    }

    @Post('listchannels')
    async executeListChannels(): Promise<string> {
        try {
            return this.ptarmiganService.commandExecuteShowdbGetChannels().toString();
        } catch (error) {
            return 'error';
        }
    }

    @Post('listnodes')
    async executeListNodes(): Promise<string> {
        try {
            return this.ptarmiganService.commandExecuteShowdbListGossipNode().toString();
        } catch (error) {
            return 'error';
        }
    }

    @Post('getroute')
    async executeGetRoute(@Body() dto: RouteNodeDto): Promise<string> {
        try {
            return this.ptarmiganService.commandExecuteRoutingGetRoute(dto.senderNodeId, dto.receiverNodeId).toString();
        } catch (error) {
            return 'error';
        }
    }

    // ------------------------------------------------------------------------------
    // invoice notifications
    // ------------------------------------------------------------------------------

    @Post('notification/htlcchanged') // addfinal.sh -> websocket
    async executeHtlcChangedNotification() {
        try {
            const clients = this.invoicesGateway.clients;

            const paymentHashs: AddFinalDto[] = await this.cacheService.getPaymentHashs();

            for (let paymentHash of paymentHashs) {
                const response: string = await this.ptarmiganService.requestTCP('listinvoice', [paymentHash.paymentHash]);

                const listInvoiceResponse: ListInvoiceResponseDto = JSON.parse(JSON.stringify(response));

                if (listInvoiceResponse !== null && listInvoiceResponse.result !== null) {
                    const listInvoiceReslt = listInvoiceResponse.result[0];

                    this.cacheService.delete(paymentHash.id);

                    for (let client of clients) {
                        client.send(JSON.stringify(listInvoiceReslt));
                    }
                }
            }
        } catch (error) {
            return 'error';
        }
    }

    @Post('notification/addfinal') // addfinal.sh -> lru-cache
    async executeAddFinalNotification(@Body() dto: AddFinalDto) {
        try {
            await this.cacheService.write(dto);
        } catch (error) {
            return 'error';
        }
    }

}
