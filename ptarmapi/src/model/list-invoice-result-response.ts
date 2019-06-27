import { ApiModelProperty } from '@nestjs/swagger';

export class ListInvoiceResultResponseDto {

    @ApiModelProperty(
        {
            required: true
        },
    )
    state: string;

    @ApiModelProperty(
        {
            required: true
        },
    )
    hash: string;

    @ApiModelProperty(
        {
            required: true
        },
    )
    amount_msat: number;

    @ApiModelProperty(
        {
            required: true
        },
    )
    creation_time: string;

    @ApiModelProperty(
        {
            required: true
        },
    )
    expiry: number;

    @ApiModelProperty(
        {
            required: true
        },
    )
    bolt11: string;
}