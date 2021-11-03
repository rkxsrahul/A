package web

import (
	"log"
	"os/exec"
)

func RunBashCommand(url, path, header string) (string, map[string]interface{}) {
	mapd := make(map[string]interface{})

	cmd := exec.Command("bash", path, url)
	out, err := cmd.Output()
	if err != nil {
		log.Println(header, " ", err.Error(), cmd.Args)
		mapd["error"] = true
		mapd["header"] = header
		mapd["message"] = "Some error in scanning the URL. Please try after sometime"
		mapd["error_message"] = err.Error()

		return "", mapd
	}
	scriptOut := string(out)
	if scriptOut == " " || scriptOut == "" {
		log.Println(cmd.Args)
	}

	log.Println("----------------------------->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", header)
	log.Println(scriptOut, mapd, header)
	log.Println("-------------------------------->>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", header)
	return scriptOut, mapd
}
