import { ApiModelProperty } from '@nestjs/swagger';

export class listPaymentDto {
    @ApiModelProperty(
        {
            required: true,
            description: '--listpayment=0',
        },
    )
    listpayment: number;
}
