# call scripts

## abstruct

ptarmd call `install/<NODE DIR>/scripts/*.sh` on event happens.

1. [started.sh](#started.sh)
2. [connected.sh](#connected.sh)
3. [disconnected.sh](#disconnected.sh)
4. [established.sh](#established.sh)
5. [payment.sh](#payment.sh)
6. [addfinal.sh](#addfinal.sh)
7. [fulfill.sh](#fulfill.sh)
8. [fail.sh](#fail.sh)
9. [htlcchanged.sh](#htlcchanged.sh)
10. [closed.sh](#closed.sh)
11. [dbclosed.sh](#dbclosed.sh)
12. [error.sh](#error.sh)

### started.sh

ptarmd started.

### connected.sh

connected peer node.

### disconnected.sh

disconnected peer node.

### established.sh

channel established.

### payment.sh

* receive payment request from JSON-RPC(including `ptarmcli`)
* routing success

### addfinal.sh

* `update_add_htlc` received and the preimage is mine.
* `revoke_and_ack` message exchanged.

This is useful for faster receiving action.

### fulfill.sh

### fail.sh

### htlcchanged.sh

`revoke_and_ack` message exchanged.

### closed.sh

### dbclosed.sh

channel closed and remove channel from database.

### error.sh

`error` message received.
