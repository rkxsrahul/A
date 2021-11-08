package nats

import (
	"encoding/json"
	"log"
	"os"
	"sync"

	"git.xenonstack.com/util/continuous-security-backend/config"
	"git.xenonstack.com/util/continuous-security-backend/src/database"
	"github.com/nats-io/nats.go"
)

//printMsg : To print when a msg is recieved
func printMsg(m *nats.Msg, i int) {
	log.Printf("[#%d] Received on [%s] Pid[%d]: '%s'", i, m.Subject, os.Getpid(), string(m.Data))
}

type Result struct {
	Data   map[string]interface{} `json:"data"`
	UUID   string                 `json:"uuid"`
	Method string                 `json:"method"`
	Header string                 `json:"header"`
}

//Subscribe : This function is used to initiate subscriber
func Subscribe() {
	var wg sync.WaitGroup
	nc := config.NC
	i := 0
	subject := "scan-results"
	wg.Add(1)

	// Subscribe
	if _, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		i++
		printMsg(msg, i)
		go saveToDatabase(msg)
	}); err != nil {
		log.Fatal(err)
	}

	// Wait for a message to come in
	wg.Wait()
}

//Subscribe : This function is used to initiate subscriber
func NodeSubscribe() {
	var wg sync.WaitGroup
	nc := config.NC
	i := 0
	subject := "node-scan-results"
	wg.Add(1)

	// Subscribe
	if _, err := nc.Subscribe(subject, func(msg *nats.Msg) {
		i++
		printMsg(msg, i)
		go saveNodeResult(msg)
	}); err != nil {
		log.Fatal(err)
	}

	// Wait for a message to come in
	wg.Wait()
}

func saveToDatabase(msg *nats.Msg) {
	var data Result
	err := json.Unmarshal(msg.Data, &data)
	if err != nil {
		log.Println("JSON unmarshal: saveToDatabase", err)
		log.Println(string(msg.Data))
		return
	}
	database.SaveRow(data.Data, data.UUID, data.Header, data.Method)
}

func saveNodeResult(msg *nats.Msg) {
	var data Result
	err := json.Unmarshal(msg.Data, &data)
	if err != nil {
		log.Println("JSON unmarshal: saveToDatabase", err)
		log.Println(string(msg.Data))
		return
	}
	log.Println("=-=-=--==--==-=-=-")
	log.Println(data)
	log.Println("=-=-=--==--==-=-=-")
	database.SaveNoderesult(data.Data, data.UUID)
}
