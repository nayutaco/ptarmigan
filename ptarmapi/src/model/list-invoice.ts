import { ApiModelProperty } from '@nestjs/swagger';

export class ListInvoiceDto {

    @ApiModelProperty(
        {
            required: false,
        },
    )
    paymentHash?: string;
}
