import { ApiModelProperty } from '@nestjs/swagger';

export class PeerNodeDto {
    @ApiModelProperty(
        {
            required: true,
        },
    )
    peerNodeId: string;
}
