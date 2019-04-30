import { ApiModelProperty } from '@nestjs/swagger';

export class PeerDto {
    @ApiModelProperty(
        {
            required: true,
        },
    )
    peerNodeId: string;

    @ApiModelProperty(
        {
            required: true,
        },
    )
    peerAddr: string;

    @ApiModelProperty(
        {
            required: true,
            default: 9735,
        },
    )
    peerPort: number;
}
