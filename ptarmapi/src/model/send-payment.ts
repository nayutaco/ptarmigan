import { ApiModelProperty } from '@nestjs/swagger';

export class SendPaymentDto {
    @ApiModelProperty(
        {
            required: true,
            description: 'bolt11 invoice',
        },
    )
    bolt11: string;

    @ApiModelProperty(
        {
            required: true,
            description: 'add amount msat',
            default: 0,
        },
    )
    addAmountMsat: number;
}
