package web

import (
	"encoding/json"
	"regexp"

	"git.xenonstack.com/util/continuous-security-backend/config"
	"git.xenonstack.com/util/continuous-security-backend/src/database"
	"git.xenonstack.com/util/continuous-security-backend/src/nats"
)

const (
	ansi               string = "[\u001B\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[a-zA-Z\\d]*)*)?\u0007)|(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PRZcf-ntqry=><~]))"
	commonErrorMessage string = "SSL certificate not found"
)

var re = regexp.MustCompile(ansi)

func sslAvailable(url, uuid, method string) string {
	header := "SSL Not Available"
	data, mapd := RunBashCommand(url, config.PersistStoragePath+headerFileSlug(header), header)
	if data != "" {
		mapd["secure"] = "false"
		mapd["header"] = header
		mapd["heading"] = "SSL not available"
		mapd["impact"] = "HIGH"
		mapd["description"] = "SSL is used to keep sensitive information sent across the Internet, Therefore SSL should be supported for this site"
	} else {
		mapd["secure"] = "true"
		mapd["header"] = header
		mapd["heading"] = "SSL is available"
		mapd["impact"] = "PASS"
		mapd["description"] = "SSL is available for this Site"
	}
	database.SaveRow(mapd, uuid, header, method)
	return mapd["impact"].(string)
}

func request(url, uuid, method, status, subject string) {
	data := nats.RequestData{
		Method: method,
		URL:    url,
		UUID:   uuid,
		Status: status,
	}
	body, _ := json.Marshal(data)
	nats.Publish(body, subject)
}

func gitRequest(url, uuid, method, branch, subject string) {
	data := nats.RequestData{
		Method: method,
		URL:    url,
		UUID:   uuid,
		Status: "",
		Branch: branch,
	}
	body, _ := json.Marshal(data)
	nats.Publish(body, subject)
}
