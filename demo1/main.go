package main

import (
	"github.com/casbin/casbin/v2"
	"log"
)

func check(e *casbin.Enforcer,sub,obj,act string) {
	enforce, err := e.Enforce(sub, obj, act)
	if err != nil {
		log.Fatalln("check error: ",err)
	}

	if enforce {
		log.Printf("%s %s %s SUCCESS \n",sub,obj,act)
	}else {
		log.Printf("%s %s %s ERROR \n",sub,obj,act)
	}
}

func main() {
	enforcer, err := casbin.NewEnforcer("./model.conf", "./policy.csv")
	if err != nil {
		log.Fatalln("new enforcer err: ",err)
	}

	check(enforcer, "dajun", "data1", "read")
	check(enforcer, "lizi", "data2", "write")
	check(enforcer, "dajun", "data1", "write")
	check(enforcer, "dajun", "data2", "read")
}
