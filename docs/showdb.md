# showdb

## NAME

`showdb` - show database using `ptarmd`

## SYNOPSIS

    swhodb [options]

### options

* `-d` : DB directory(= contain `db` directory). use current directory if not specified.
* `-w` : wallet info
* `-s` : self info
* `-q` : closed self info
* `-c` : channel_announcement/channel_update
* `-n` : node_announcement
* `-v` : DB version
* `-a` : (internal)announcement received/sent node_id list
* `-k` : (internal)routing skip channel list
* `-i` : (internal)paying invoice list

## DESCRIPTION

Show information in `ptarmd` database.

## SEE ALSO

## AUTHOR

Nayuta Inc.
