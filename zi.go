/*
zi — generate file for 'iptables-restore -n'

The program reads CSV dump of the registry from stdin and writes ipset config
to stdout.

Read the code if you want to change the behavior.

WARNING: dump.csv IPs and nets count is greater than default (2^16) capacity
of the ipset hast:net.  Creating set for up to 16777216 (2^24) elements works
for me.  The command below creates the hash:net with enough capacity.

  ipset create myset hash:net maxelem 16777216


Usage

    # create set
    ipset create zapret-info hash:net
    # generate and populate set
    zi <dump.csv | ipset restore


IO redirection

    # create set
    ipset create zapret-info hash:net
    # generate and populate set
    zi -i dump.csv -o ipset.conf
    ipset restore -file ipset.conf


Update entry timeout

    # create set
    ipset create zapret-info hash:net timeout 3600
    # generate and populate set
    zi -t 3600 <dump.csv | ipset restore


Custom set name

    # create set
    ipset create "fuck russian rkn" hash:net
    # generate and populate set
    zi -n "fuck russian rkn" <dump.csv | ipset restore


Routing setup for transparent TCP proxy

    ipset create zapret-info hash:net timeout 86400 maxelem 16777216
    iptables -t nat -I PREROUTING -p tcp -m set --match-set zapret-info dst -j REDIRECT --to-port 9040
    iptables -t nat -I OUTPUT     -p tcp -m set --match-set zapret-info dst -j REDIRECT --to-port 9040
*/
package main

import (
	"io"
	"os"
	"fmt"
	"flag"
	"strings"
	"encoding/csv"
	"golang.org/x/text/encoding/charmap"
)

var (
	targetSet = "zapret-info"
	timeout = -1
)

func init() {
	input := ""
	output := ""
	// IO options
	flag.StringVar(&input,  "i", input, "read from file")
	flag.StringVar(&output, "o", output, "write to file")
	// format options
	flag.StringVar(&targetSet, "n", targetSet, "target set name")
	flag.IntVar(&timeout, "t", timeout, "set entry timeout")

	flag.Parse()

	reopen(&os.Stdin, input, os.Open)
	reopen(&os.Stdout, output, os.Create)
}

func reopen(a **os.File, fp string, fopen func(string) (*os.File, error)) {
	if fp == "" {
		return
	}
	b, err := fopen(fp)
	if err != nil {
		panic(err)
	}
	*a = b
}

func main() {
	r := csv.NewReader(charmap.Windows1251.NewDecoder().Reader(os.Stdin))
	r.Comma = ';'
	r.FieldsPerRecord = -1

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
}

func addRule(addrs []string, domain string, urls []string, department string, unknown string, date string) {
	fmt.Println("##", department, date)
	fmt.Println("##", unknown)
	if domain != "" {
		fmt.Println("##", domain)
	}
	for _, url := range urls {
		// NOTE: ipset's line buffer size is only 1024 chars.
		l := 1020
		if len(url) > l {
			url = url[:l]
			fmt.Println("## ERROR: URL below is too long")
		}
		fmt.Println("##", url)
	}
	for _, addr := range addrs {
		fmt.Printf("add -! %q %q", targetSet, addr)
		if timeout >= 0 {
			fmt.Print(" timeout ", timeout)
		}
		fmt.Println()
	}
}
