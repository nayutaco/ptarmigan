#!/bin/sh
echo "cltv_expiry_delta=36\nhtlc_minimum_msat=0\nfee_base_msat=10\nfee_prop_millionths=100" > anno.conf
echo "dust_limit_sat=546\nmax_htlc_value_in_flight_msat=18446744073709551615\nchannel_reserve_sat=0\nhtlc_minimum_msat=0\nto_self_delay=40\nmax_accepted_htlcs=6\nmin_depth=1" > establish.conf
