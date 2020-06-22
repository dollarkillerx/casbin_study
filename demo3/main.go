package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"log"
)

func check(enforcer *casbin.Enforcer, sub, dom, obj, act string) {
	enforce, err := enforcer.Enforce(sub, dom, obj, act)
	if err != nil {
		log.Fatalln(err)
	}

	if enforce {
		fmt.Printf("%s %s %s %s SUCEESS\n", sub, dom, obj, act)
	} else {
		fmt.Printf("%s %s %s %s ERROR\n", sub, dom, obj, act)
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	enforcer, err := casbin.NewEnforcer("./rbac.conf", "./rbac.csv")
	if err != nil {
		log.Fatalln(err)
	}

	check(enforcer, "user1", "tenant1", "data1", "read")
	check(enforcer, "admin", "tenant1", "data2", "read")
	check(enforcer, "user2", "tenant2", "data2", "read")
	check(enforcer, "user", "tenant2", "data2", "read")
}
