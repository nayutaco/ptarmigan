import { ApiModelProperty } from '@nestjs/swagger';

export class FeeDto {
    @ApiModelProperty(
        {
            required: true,
            description: 'feerate per kw',
        },
    )
    feeratePerKw: number;
}
