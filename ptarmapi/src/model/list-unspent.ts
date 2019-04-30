import { ApiModelProperty } from '@nestjs/swagger';

export class ListUnspentDto {
    @ApiModelProperty(
        {
            required: true,
            default: 1,
            minimum: 0,
            maximum: 9999999,
        },
    )
    minconf: number;

    @ApiModelProperty(
        {
            required: true,
            default: 9999999,
            minimum: 0,
            maximum: 9999999,
        },
    )
    maxconf: number;

    @ApiModelProperty(
        {
            type: [String],
            required: false,
            default: [],
        },
    )
    addresses: string[];
}
