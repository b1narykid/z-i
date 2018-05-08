package main
// zi -- generate file for 'iptables-restore -n'
// reads from stdin, writes to stdout.
//
//  Usage:
//      # generate ruleset
//      zi <dump.csv >dump.rules
//
//      # parse and construct the ruleset, but do not commit it
//      iptable-restore -t dump.rules
//
//      # commit without flushing previous table contents
//      iptable-restore -n dump.rules
//
// By default creates TORSOCKS chain in nat table (author uses redsocks and tor)
// and populates it with TCP `REDIRECT` from all blocked IPs and networks to
// port 9040 (transparent proxy).  Then it jumps from PREROUTING and OUTPUT to
// TORSOCKS for TCP connections.
//
// Read the code if you want to change the behavior.

import (
	"io"
	"os"
	"fmt"
	"strings"
	"encoding/csv"
	"golang.org/x/text/encoding/charmap"
)

const (
	transport = 9040
	chain = "TORSOCKS"
	maxDestinationsPerRule = 4
)

func main() {
	r := csv.NewReader(charmap.Windows1251.NewDecoder().Reader(os.Stdin))
	r.Comma = ';'
	r.FieldsPerRecord = -1

	before()
	for {
		record, err := r.Read()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}

		if len(record) != 6 {
			fmt.Println("#", "ignored record %q", record)
			continue
		}

		l := func(s string) []string {
			if s == "" {
				return nil
			}

			components := strings.Split(s, " | ")
			r := make([]string, 0, len(components))
			for _, c := range components {
				if c != "" {
					r = append(r, c)
				}
			}
			return r
		}

		addRule(l(record[0]), // IP addresses and networks
		          record[1] , // domain name (sometimes with wildcards)
		        l(record[2]), // URLs
		          record[3] , // department that blocked the resource
		          record[4] , // ???
		          record[5] ) // date added
	}
	after()
}

func before() {
	fmt.Println("*nat")
	fmt.Println("-N", chain)
}

func addRule(addrs []string, domain string, urls []string, department string, unknown string, date string) {
	fmt.Println("##", department, date)
	fmt.Println("##", unknown)

	if domain != "" {
		fmt.Println("##", domain)
	}
	for _, url := range urls {
		fmt.Println("##", url)
	}
	for len(addrs) > 0 {
		l := len(addrs)
		if l > maxDestinationsPerRule {
			l = maxDestinationsPerRule
		}

		fmt.Println("-A", chain, "-d", strings.Join(addrs[:l], ","), "-p tcp -j REDIRECT --to-port", transport)

		if len(addrs) > l {
			addrs = addrs[l:]
			continue
		}
		addrs = nil
	}
}

func after() {
	fmt.Println("-A", chain, "-j RETURN")
	fmt.Println("-I PREROUTING -p tcp -j", chain)
	fmt.Println("-I OUTPUT -p tcp -j", chain)
	fmt.Println("COMMIT")
}
