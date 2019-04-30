import { ApiModelProperty } from '@nestjs/swagger';

export class FundDto {
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
    fundingSat: number;

    @ApiModelProperty(
        {
            required: true,
        },
    )
    pushMsat: number;

    @ApiModelProperty(
        {
            required: false,
            default: 0,
        },
    )
    feeratePerKw: number;
}
