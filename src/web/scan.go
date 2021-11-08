package web

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/xid"

	"git.xenonstack.com/util/continuous-security-backend/config"
	"git.xenonstack.com/util/continuous-security-backend/src/database"
)

type URL struct {
	URL   string `json:"url" binding:"required"`
	FName string `json:"first_name"`
	LName string `json:"last_name"`
	Email string `json:"email"`
}

// Scan is an api handler
func Scan(c *gin.Context) {

	var data URL
	if err := c.BindJSON(&data); err != nil {
		log.Println(err)
		c.JSON(400, gin.H{
			"error":   true,
			"message": "Please pass url of website",
		})
		return
	}

	url, err := CheckUser(data.URL)
	if err != nil {
		url = data.URL
	}

	cmd := exec.Command("bash", "validate.sh", url)
	out, err := cmd.Output()
	if err != nil {
		c.JSON(400, gin.H{
			"error":   true,
			"message": err.Error(),
		})
		return
	}
	code := strings.Split(string(out), "\n")
	script := false
	for _, element := range code {
		i, err := strconv.Atoi(element)
		if err != nil {
			continue
		}
		if i < 400 {
			script = true
		}
	}
	log.Println(script)
	if !script {
		c.JSON(400, gin.H{
			"error":   true,
			"message": "Please Try again and check the URL",
		})
		return
	}
	data.URL = url
	var info database.RequestInfo
	info.URL = url
	info.IP = c.ClientIP()
	info.Agent = c.Request.UserAgent()
	info.Timestamp = time.Now().Unix()
	info.UUID = xid.New().String()
	info.Name = data.FName + " " + data.LName
	info.Email = data.Email
	db := config.DB

	err = db.Create(&info).Error
	log.Println(err)
	result := sslAvailable(data.URL, info.UUID, "Website Security")
	if result != "PASS" {
		go request(data.URL, info.UUID, "Website Security", "fail", "tlsVersions")                //1
		go request(data.URL, info.UUID, "Website Security", "fail", "beast")                      //2
		go request(data.URL, info.UUID, "Website Security", "fail", "breach")                     //3
		go request(data.URL, info.UUID, "Website Security", "fail", "crime")                      //4
		go request(data.URL, info.UUID, "Website Security", "fail", "freak")                      //5
		go request(data.URL, info.UUID, "Website Security", "fail", "heartbleed")                 //6
		go request(data.URL, info.UUID, "Website Security", "fail", "logjam")                     //7
		go request(data.URL, info.UUID, "Website Security", "fail", "poodle")                     //8
		go request(data.URL, info.UUID, "Website Security", "fail", "certificateValid")           //9
		go request(data.URL, info.UUID, "HTTP Security Headers", "fail", "hsts")                  //10
		go request(data.URL, info.UUID, "HTTP Security Headers", "fail", "expectCt")              //11
		go request(data.URL, info.UUID, "HTTP Security Headers", "fail", "contentSecurityPolicy") //12
		go request(data.URL, info.UUID, "HTTP Security Headers", "fail", "xss")                   //13
		go request(data.URL, info.UUID, "HTTP Security Headers", "fail", "xContentTypeOption")    //14
		go request(data.URL, info.UUID, "HTTP Security Headers", "fail", "referrerPolicy")        //15
		go request(data.URL, info.UUID, "HTTP Security Headers", "fail", "xFrameOption")          //16
		// go request(data.URL, info.UUID, "Website Security", "fail","signatureAlgo")
		//go request(data.URL, info.UUID, "Website Security", "fail","chainTrust")
	} else {
		go request(data.URL, info.UUID, "Website Security", "", "tlsVersions")                //1
		go request(data.URL, info.UUID, "Website Security", "", "beast")                      //2
		go request(data.URL, info.UUID, "Website Security", "", "breach")                     //3
		go request(data.URL, info.UUID, "Website Security", "", "crime")                      //4
		go request(data.URL, info.UUID, "Website Security", "", "freak")                      //5
		go request(data.URL, info.UUID, "Website Security", "", "heartbleed")                 //6
		go request(data.URL, info.UUID, "Website Security", "", "logjam")                     //7
		go request(data.URL, info.UUID, "Website Security", "", "poodle")                     //8
		go request(data.URL, info.UUID, "Website Security", "", "certificateValid")           //9
		go request(data.URL, info.UUID, "HTTP Security Headers", "", "hsts")                  //10
		go request(data.URL, info.UUID, "HTTP Security Headers", "", "expectCt")              //11
		go request(data.URL, info.UUID, "HTTP Security Headers", "", "contentSecurityPolicy") //12
		go request(data.URL, info.UUID, "HTTP Security Headers", "", "xss")                   //13
		go request(data.URL, info.UUID, "HTTP Security Headers", "", "xContentTypeOption")    //14
		go request(data.URL, info.UUID, "HTTP Security Headers", "", "referrerPolicy")        //15
		go request(data.URL, info.UUID, "HTTP Security Headers", "", "xFrameOption")          //16
		// go request(data.URL, info.UUID, "Website Security", "","signatureAlgo")
		// go request(data.URL, info.UUID, "Website Security", "","chainTrust")
	}
	go request(data.URL, info.UUID, "Website Security", "", "serverInformationHeaderExposed")
	//	go request(data.URL, info.UUID, "Website Security", "", "missingSecurityHeaders")
	go request(data.URL, info.UUID, "Website Security", "", "redirectToHTTPS")
	go request(data.URL, info.UUID, "Website Security", "", "httpMethodsUsed")
	go request(data.URL, info.UUID, "Website Security", "", "potentially")
	go request(data.URL, info.UUID, "Website Security", "", "expiryTime")

	go request(data.URL, info.UUID, "Email Security", "", "dMARCPolicy")
	go request(data.URL, info.UUID, "Email Security", "", "dMARCPercentage")
	go request(data.URL, info.UUID, "Email Security", "", "dMARCReject")

	go request(data.URL, info.UUID, "Network Security", "", "dNSSECEnabled")
	go request(data.URL, info.UUID, "Network Security", "", "openPorts")

	err = HubspotSubmission(data)
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	c.JSON(200, gin.H{
		"error":         false,
		"data":          info,
		"info":          data,
		"error_message": msg,
	})
}
func CheckUser(url string) (string, error) {

	spliturl := strings.Split(url, "://")
	schema := "https://"

	if len(spliturl) > 1 {
		url = spliturl[1]
	} else {
		url = spliturl[0]
	}
	method := "GET"
	// splitdomain := strings.Split(url, ".")
	var domain string

	domain = schema + url

	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(method, domain, nil)
	if err != nil {
		log.Println(err)
		return "", err
	}

	//	req.Header.Set("Location", "Chandigarh")
	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		//	return "", err
	}

	if res == nil {

		if !strings.HasPrefix(url, "www") {
			domain = schema + "www." + url
		}
		req, err = http.NewRequest(method, domain, nil)
		if err != nil {
			log.Println(err)
			return "", err
		}
		res, err = client.Do(req)
		if err != nil {
			log.Println(err)
			//	return "", err
		}
		if res == nil {
			if strings.HasPrefix(spliturl[0], "https") {
				log.Println(err)
				return domain, err
			}
			domain = strings.Replace(domain, "https", "http", 1)
			req, err = http.NewRequest(method, domain, nil)
			if err != nil {
				log.Println(err)
				return "", err
			}
			res, err = client.Do(req)
			if err != nil {
				log.Println(err)
				return "", err
			}

			defer res.Body.Close()
			if res.StatusCode > 300 {
				return res.Request.URL.Scheme + "://" + res.Request.URL.Hostname(), nil
			}
			return res.Request.URL.Scheme + "://" + res.Request.URL.Hostname(), nil
		}
	}
	defer res.Body.Close()
	if res.StatusCode > 300 {
		log.Println(res.Request.URL.Scheme+"://"+res.Request.URL.Hostname(), nil)
		return res.Request.URL.Scheme + "://" + res.Request.URL.Hostname(), nil
	}
	return res.Request.URL.Scheme + "://" + res.Request.URL.Hostname(), nil
}

func HubspotSubmission(data URL) error {

	db := config.DB

	list := database.RequestInfo{}
	db.Where("email=?", data.Email).Find(&list)

	if list.ID != 0 {
		log.Println(list)
		return nil
	}
	url := "https://api.hsforms.com/submissions/v3/integration/submit/" + config.Conf.Hubspot.PortalID + "/" + config.Conf.Hubspot.WebsiteID
	method := "POST"

	payload := strings.NewReader(`{
  "fields": [
    {
      "name": "email",
      "value": "` + data.Email + `"
    },
    {
      "name": "0-2/website",
      "value": "` + data.URL + `"
    },
    {
      "name": "firstname",
      "value": "` + data.FName + `"
    },
    {
      "name": "lastname",
      "value": "` + data.LName + `"
    }
  ]
}
      `)

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)

	req.Header.Add("Content-Type", "application/json")
	if err != nil {
		log.Println(err)
		return err
	}

	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		return err
	}
	fmt.Println(string(body))
	log.Println(err)
	return nil
}

func GitScan(c *gin.Context) {
	mapd := make(map[string]interface{})
	var data database.NodeInfo
	if err := c.BindJSON(&data); err != nil {
		log.Println(err)
		c.JSON(400, gin.H{
			"error":   true,
			"message": "Please pass Git URL",
		})
		return
	}
	giturlsplit1 := strings.Split(data.GitURL, "/")
	if len(giturlsplit1) < 5 {
		mapd["error"] = true
		mapd["message"] = "Please pass the the valid url"
		c.JSON(400, mapd)
		return
	}

	projectname := giturlsplit1[3]
	reponame := giturlsplit1[4]
	Splitrepo := strings.Split(reponame, ".")
	finalrepo := Splitrepo[0]

	//finalurl is the url to be executed to get the list of branches
	finalurl := "https://api.github.com/repos/" + projectname + "/" + finalrepo
	language, err := checkLanguage(finalurl)
	if err != nil {
		log.Println(err)
		mapd["error"] = true
		mapd["message"] = err.Error()
		c.JSON(400, mapd)
		return
	}
	if language != "JavaScript" {
		mapd["error"] = true
		mapd["message"] = "Please pass the valid url"
		c.JSON(400, mapd)
		return

	}
	var info database.NodeInfo
	info.GitURL = data.GitURL
	info.IP = c.ClientIP()
	info.Agent = c.Request.UserAgent()
	info.Timestamp = time.Now().Unix()
	info.UUID = xid.New().String()
	info.Name = data.Name
	info.Email = data.Email
	info.Branch = data.Branch
	db := config.DB
	err = db.Create(&info).Error
	log.Println(err)
	go gitRequest(data.GitURL, info.UUID, "Node Scan", data.Branch, "nodeScan")
	c.JSON(200, gin.H{
		"error": false,
		"data":  info,
		"info":  data,
	})
}

func checkLanguage(url string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", err
	}
	type UsedLanguage struct {
		Language string `json:"language"`
	}
	var language UsedLanguage
	err = json.Unmarshal(body, &language)
	if err != nil {
		return "", err
	}
	return language.Language, err
}
