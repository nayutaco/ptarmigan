import {
    SubscribeMessage,
    WebSocketGateway,
    WebSocketServer,
    OnGatewayConnection,
    WsResponse,
    OnGatewayInit,
    OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'ws';
import { Logger } from '@nestjs/common';

@WebSocketGateway({ path: '/ws' })
export class InvoicesGateway implements OnGatewayConnection, OnGatewayInit, OnGatewayDisconnect {

    private logger = new Logger('InvoicesGateway');
    clients: Socket[] = [];

    @WebSocketServer()
    server: Server;

    afterInit(server: Server) {
        this.clients = [];
        this.logger.log('websocket server start');
    }

    handleConnection(client: Socket) {
        if (this.notHasClientId(this.clients, client.id)) {
            this.clients.push(client);
        }
    }

    handleDisconnect(client: Socket) {
        this.clients = this.removeById(this.clients, client.id);
    }

    private removeById(fromClients: Socket[], id: string) {
        const result = fromClients.findIndex((client) => {
            return client.id === id;
        });
        if (result >= 0) {
            fromClients.splice(result, 1);
        }
        return fromClients;
    }

    private notHasClientId(fromClients: Socket[], id: string): boolean {
        const result = fromClients.findIndex((client) => {
            return client.id === id;
        });
        if (result >= 0) {
            return false;
        }
        return true;
    }

}