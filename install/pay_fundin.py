import os
import sys
import json
import subprocess
from decimal import*
import datetime

'''
+-----+
| IN0 +---+
+-----+   |     fund_in                   funding_tx
          |    +-----+--------------+    +-------+-------------+    +--------+
+-----+   +--->+     |  funding_sat +--->+       | funding_sat +--->+ 2-of-2 |
| IN1 +--+     |     |     +        |    +-------+-------------+    +--------+
+-----+  +---->+     |    fundfee   |                  fundfee
               |     +--------------+
  ...          |     | (change)     |
          +--->+     |              |
+-----+   |    +-----+--------------+
| INn +---+                    txfee
+-----+
'''


def fund_in(funding_sat, push_msat):
    fundamount = float(funding_sat) / 100000000
    fundamount = round(fundamount, 8)

    sum = 0         # input amount
    cmd_sum = ''
    fundsum = 0     # output amount + txfee

    feerate = estimatefeerate()

    #New UTXO has 'fundamount' plus 'fundfee'.
    fundfee = round(227 * feerate / 1000, 8)
    fundamount += fundfee

    sum, cmd_sum, fundsum, txfee, estimate_vsize = aggregate_inputs(fundamount, feerate)
    if sum < fundamount:
        print("ERROR: You don't have enough amount.")
        return

    dispfundamount = "{0:.8f}".format(round(fundamount, 8))
    change = round(sum - fundamount - txfee, 8)

    print("[Size] " + str(estimate_vsize) + " bytes")
    print("[Send] " + dispfundamount + " btc")

    #TX OUTPUT
    newaddr = getnewaddress()
    cmd_sum = cmd_sum +  " \'[{\"" + newaddr + "\":" + dispfundamount + "}"

    ret, signhex = create_tx(cmd_sum, sum, fundsum, change)
    if not ret:
        print('ERROR: create transaction was failed.')
        return

    #fee calclate 2
    vsize = get_vsize(signhex)
    if vsize != estimate_vsize:
        print('vsize not same(' + str(vsize) + ') --> recalc')
        txfee, fundsum, change = calc_txfee(sum, vsize, feerate, fundamount)
        ret, signhex = create_tx(cmd_sum, sum, fundsum, change)
        if not ret:
            print('ERROR: create transaction was failed.')
            return

    sendtx = signrawtx(signhex)
    if 'error' in sendtx:
        print('ERROR: sendtransaction was failed.')
        print('--------')
        print(sendtx)
        return
    print("[Address] " + newaddr)
    print("[TXID] " + sendtx)

    # lock unspent(NOTE: not auto unlock!!)
    lockvout = lockunspent(sendtx)
    print('[LOCK]', lockvout)

    #CREATE CONF
    name = str("fund_" + datetime.datetime.now().strftime("%Y%m%d%H%M%S") + ".conf")
    create_conf(name, sendtx, newaddr, funding_sat, push_msat)
    print('[CREATE] ' + name)


def aggregate_inputs(fundamount, feerate):
    sum = 0
    txlist = []
    cmd_sum = ''
    txfee = 0
    p2wpkh = 0
    p2sh = 0
    p2pkh = 0

    subprocess.run("bitcoin-cli listunspent 0 > list.json", shell = True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    a = open("list.json", 'r')
    lu = json.load(a)
    a.close()
    os.remove("list.json")

    for i in range(len(lu)):
        addrmk = lu[i]['scriptPubKey']
        if addrmk[:2] == "00" :
            p2wpkh += 1
        elif addrmk[:2] == "a9" :
            p2sh += 1
        elif addrmk[:2] == "76" :
            p2pkh += 1
        else:
            #maybe P2PK
            continue

        sum += lu[i]['amount']
        txlist.append("{\"txid\":\"" + str(lu[i]['txid']) + "\",\"vout\":" + str(lu[i]['vout']) + "}")

        if sum >= fundamount:
            #TX INPUT
            for x in txlist :
                if x == txlist[0] :
                    cmd_sum = "\'["
                    cmd_sum = cmd_sum + x
                else :
                    cmd_sum = cmd_sum + "," + x
            cmd_sum += "]\'"

            #TX AMOUNT
            #   version(4)
            #   mark,flags(2)
            #   vin_cnt(1)
            #   vin(signature length=73)
            #       native P2WPKH = outpoint(36) + scriptSig(1) + sequence(4) + witness(1 + 1+73 + 1+33)/4
            #       nested P2WPKH = outpoint(36) + scriptSig(23) + sequence(4) + witness(1 + 1+73 + 1+33)/4
            #       P2PKH         = outpoint(36) + scriptSig(1 + 1+73 + 1+33) + sequence(4)
            #   vout_cnt(1)
            #   vout
            #       mainout = P2WPKH(32)
            #       change  = P2WPKH(32)
            #   locktime(4)
            estimate_vsize = 76 + (p2wpkh * 69 + p2sh * 91 + p2pkh * 149)
            txfee, fundsum, _ = calc_txfee(sum, estimate_vsize, feerate, fundamount)
            if fundsum <= sum :
                #print('  p2wpkh=' + str(p2wpkh) + ', p2sh=' + str(p2sh) + ', p2pkh=' + str(p2wpkh))
                break

    return sum, cmd_sum, fundsum, txfee, estimate_vsize


def calc_txfee(sum, vsize, feerate, fundamount):
    txfee = round(vsize * feerate / 1000, 8)
    fundsum = fundamount + txfee
    change = round(sum - fundamount - txfee, 8)
    return txfee, fundsum, change


def create_tx(cmd_sum, sum, fundsum, change):
    if sum - fundsum >  0.00000547 :
        changeaddr = getnewaddress()
        cmd = cmd_sum +  ",{\"" +changeaddr + "\":" + str(change) + "}"
    else:
        cmd = cmd_sum
    cmd = cmd + "]\'"
    return create_sign_tx(cmd)


def estimatefeerate():
    feesatpkb = subprocess.run("bitcoin-cli estimatesmartfee 6", shell = True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    feesatpkb = feesatpkb.stdout.decode("utf8").strip()
    feerate = json.loads(feesatpkb)['feerate']
    return feerate


def getnewaddress():
    newaddr = subprocess.run("bitcoin-cli getnewaddress", shell = True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    newaddr = newaddr.stdout.decode("utf8").strip()
    return newaddr


def create_sign_tx(cmd):
    createraw = subprocess.run(("bitcoin-cli createrawtransaction " + cmd), shell = True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    createraw = createraw.stdout.decode("utf8").strip()

    sign = subprocess.run(("bitcoin-cli signrawtransactionwithwallet "+ createraw), shell = True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    sign = sign.stdout.decode("utf8").strip()
    sign.replace('True', 'true')
    signhex = json.loads(sign)['hex']
    signcomplete = json.loads(sign)['complete']
    if signcomplete:
        return True, signhex
    else:
        print("ERROR: signrawtransaction was failed.")
        return False, None


def signrawtx(signhex):
    send = subprocess.run(("bitcoin-cli sendrawtransaction " + signhex), shell = True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    sendtx = send.stdout.decode("utf8").strip()
    return sendtx


def lockunspent(sendtx):
    outpoint = '{\\"txid\\":\\"' + sendtx + '\\",\\"vout\\":0}'
    lockvout = subprocess.run(('bitcoin-cli lockunspent false "[' + outpoint + ']"'), shell = True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return lockvout.stdout.decode("utf8").strip() == 'true'


def get_vsize(signhex):
    dectx = subprocess.run(("bitcoin-cli decoderawtransaction "+ signhex), shell = True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    dectx = json.loads(dectx.stdout.decode("utf8").strip())
    vsize = int(dectx['vsize'])
    return vsize


def create_conf(name, sendtx, newaddr, funding_sat, push_msat):
    #TXID
    txid = "txid=" + sendtx + "\n"
    #TXINDEX
    cmd = "bitcoin-cli gettxout " + sendtx + " 0 | grep " + newaddr + " | wc -c"
    index = subprocess.check_output(cmd, shell = True)
    if int(index) > 0:
        txindex = "txindex=0" + "\n"
    else:
        txindex = "txindex=1" + "\n"
    #SIGNADDR
    signaddr = "signaddr=" + newaddr + "\n"
    #FUNDING AMOUNT
    funding_sat = "funding_sat=" + str(funding_sat) + "\n"
    #PUSH AMOUNT
    push_sat = "push_sat=" + str(push_msat) + "\n"
    #FEE RATE
    feerate_per_kw = "feerate_per_kw=" + "0" + "\n"

    conf = open(name, 'a')
    conf.write(txid)
    conf.write(txindex)
    conf.write(signaddr)
    conf.write(funding_sat)
    conf.write(push_sat)
    conf.write(feerate_per_kw)
    conf.close()


if __name__ == '__main__':
    args = sys.argv

    if len(args) != 3 or not args[1].isdecimal() or not args[2].isdecimal():
        print('usage:\n\t' + args[0] + ' [funding_satoshis] [push_msat m-satoshis]')
        sys.exit()

    if int(args[1]) < 100000:
        print('ERROR: funding_satoshis < 100,000 sat')
        sys.exit()
    elif int(args[1]) > 1000000:
        print('ERROR: funding_satoshis > 1,000,000 sat')
        sys.exit()
    if int(args[2]) >= int(args[1]) * 1000:
        print('ERROR: funding_satoshis * 1,000 < push_msat')
        sys.exit()

    fund_in(args[1], args[2])
