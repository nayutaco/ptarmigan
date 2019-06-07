import { ApiModelProperty } from '@nestjs/swagger';

export class ListPaymentDto {
    @ApiModelProperty(
        {
            required: true,
            description: '--listpayment=0',
        },
    )
    listpayment: number;
}
