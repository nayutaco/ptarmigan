import { ApiModelProperty } from '@nestjs/swagger';
import { ListInvoiceResultResponseDto } from './list-invoice-result-response';

export class ListInvoiceResponseDto {

    @ApiModelProperty(
        {
            required: true
        },
    )
    id: string;

    @ApiModelProperty(
        {
            required: true
        },
    )
    result: ListInvoiceResultResponseDto[];

}