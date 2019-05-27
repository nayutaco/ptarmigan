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

    @ApiModelProperty(
        {
            required: false,
        },
    )
    description?: string;

    @ApiModelProperty(
        {
            required: false,
        },
    )
    invoiceExpiry?: number;
}
