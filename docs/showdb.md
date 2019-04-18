# showdb

## NAME

`showdb` - show database using `ptarmd`

## SYNOPSIS

    showdb [options]

### options

* `--datadir [NODEDIR]` : DB directory(= contain `db` directory). use current directory if not specified.
* `--listchannnelwallet` : wallet info
* `--showchannel` : self info
* `--listclosed` : closed self info
* `--listgossipchannel` : channel_announcement/channel_update
* `--listgossipnode` : node_announcement
* `--paytowalletvin` : show `ptarmcli --paytowallet` input information
* `--version` : DB version
* `--listannounced` : (internal)announcement received/sent node_id list
* `--listskip` : (internal)routing skip channel list
* `--listinvoice` : (internal)paying invoice list

## DESCRIPTION

Show information in `ptarmd` database.

## SEE ALSO

## AUTHOR

Nayuta Inc.
