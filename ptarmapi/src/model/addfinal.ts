import { ApiModelProperty } from '@nestjs/swagger';

export class AddFinalDto {

    @ApiModelProperty(
        {
            required: true
        },
    )
    paymentHash: string;

    @ApiModelProperty(
        {
            required: false
        },
    )
    id: string;
}