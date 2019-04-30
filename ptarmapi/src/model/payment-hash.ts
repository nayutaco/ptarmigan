import { ApiModelProperty } from '@nestjs/swagger';

export class PaymentHashDto {
    @ApiModelProperty(
        {
            required: true,
            description: 'payment hash',
        },
    )
    paymentHash: string;
}
