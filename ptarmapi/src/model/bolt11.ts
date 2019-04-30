import { ApiModelProperty } from '@nestjs/swagger';

export class Bolt11Dto {
    @ApiModelProperty(
        {
            required: true,
            description: 'bolt11 invoice',
        },
    )
    bolt11: string;
}
