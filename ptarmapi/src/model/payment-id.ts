import { ApiModelProperty } from '@nestjs/swagger';

export class PaymentIdDto {
    @ApiModelProperty(
        {
            required: true,
            description: 'payment id',
        },
    )
    paymentId: number;
}
