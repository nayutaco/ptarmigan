import { ApiModelProperty } from '@nestjs/swagger';

export class RouteNodeDto {
    @ApiModelProperty(
        {
            required: true,
            pattern: '^[0-9a-fA-F].',
        },
    )
    senderNodeId: string;

    @ApiModelProperty(
        {
            required: true,
            pattern: '^[0-9a-fA-F].',
        },
    )
    receiverNodeId: string;
}
