import { ApiModelProperty } from '@nestjs/swagger';

export class InvoiceDto {
    @ApiModelProperty(
        {
            required: true,
            description: 'amount msatoshi',
        },
    )
    amountMsat: number;

    @ApiModelProperty(
        {
            required: false,
        },
    )
    minFinalCltvExpiry?: number;
}
