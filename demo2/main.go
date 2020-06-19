package main

import (
	"fmt"
	"github.com/casbin/casbin/v2"
	"log"
)

func check(enforcer *casbin.Enforcer,sub,obj,act string) {
	enforce, err := enforcer.Enforce(sub, obj, act)
	if err != nil {
		log.Fatalln(err)
	}
	if enforce {
		fmt.Printf("%s %s %s SUCEESS\n",sub,obj,act)
	}else {
		fmt.Printf("%s %s %s ERROR\n",sub,obj,act)
	}
}

func main() {
	log.SetFlags(log.Lshortfile|log.LstdFlags)

	enforcer, err := casbin.NewEnforcer("./rbac.conf", "./rbac.csv")
	if err != nil {
		log.Fatalln(err)
	}

	check(enforcer,"he1","data2","write")
	check(enforcer,"he1","data1","write")

	check(enforcer,"he2","data1","write")
	check(enforcer,"he2","data1","read")
}
