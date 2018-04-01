# FAQ

## Content Overview
* [Error: MEMORY ALLOC FAILED: mmap failed](#error-memory-alloc-failed-mmap-failed)
* [Change Currency to Mine](#change-currency-to-mine)
* [How can I mine Monero](#how-can-i-mine-monero)
* [Why is Monero named monero7](why-is-monero-named-monero7)
* [Which currency must be chosen if my fork coin is not listed](#which-currency-must-be-chosen-if-my-fork-coin-is-not-listed)

## Error: MEMORY ALLOC FAILED: mmap failed

On Linux you will need to configure large page support and increase your ulimit -l. 

To set large page support, add the following lines to /etc/sysctl.conf:
    
    vm.nr_hugepages=128

To increase the ulimit, add following lines to /etc/security/limits.conf:

    * soft memlock 262144
    * hard memlock 262144

You WILL need to log out and log back in for these settings to take affect on your user (no need to reboot, just relogin in your session).

You can also do it Windows-style and simply run-as-root, but this is NOT recommended for security reasons.

## Change Currency to Mine

If the miner is compiled for Monero and Aeon than you can change
 - the value `currency` in the config *or*
 - start the miner with the [command line option](usage.md) `--currency monero7` or `--currency aeon`
 - run `xmr-stak --help` to see all supported currencies and algorithms

## How can I mine Monero

Set the value `currency` in `pools.txt` to `monero7`.

## Why is Monero named monero7

To avoid configuration conflicts after the hard fork of Monero to the new POW with our old naming schema where all cryptonight currencies was selected by choosing `monero` as currency we decided to switch to the name `monero7`.

## Which currency must be chosen if my fork coin is not listed

If your coin you want to mine is not listed please check the documentation of the coin and try to find out if `cryptonight` or `cryptonight-lite` is the used algorithm.
Select one of these generic coin algorithms.
