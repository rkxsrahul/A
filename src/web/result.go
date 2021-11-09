package web

import (
	"encoding/json"
	"io"
	"log"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"git.xenonstack.com/util/continuous-security-backend/config"
	"git.xenonstack.com/util/continuous-security-backend/src/database"
)

// ScanResult is an api handler to get results from database scanned
func fetchFromDatabase(uuid string, result chan interface{}) {
	// uuid := c.Param("id")
	now := time.Now().Unix()
	end := time.Now().Unix()
	db := config.DB
	for end-now < 1000 {
		time.Sleep(2 * time.Second)
		end = time.Now().Unix()
		website := []database.ScanResult{}
		email := []database.ScanResult{}
		network := []database.ScanResult{}
		http := []database.ScanResult{}
		db.Where("uuid=? AND method=?", uuid, "Website Security").Order("created_at DESC").Find(&website)

		db.Where("uuid=? AND method=?", uuid, "Email Security").Order("created_at DESC").Find(&email)

		db.Where("uuid=? AND method=?", uuid, "Network Security").Order("created_at DESC").Find(&network)

		db.Where("uuid=? AND method=?", uuid, "HTTP Security Headers").Order("created_at DESC").Find(&http)

		//code for score check
		score := 100
		for i := 0; i < len(email); i++ {
			if strings.Contains(email[i].Result, `"impact":"HIGH"`) {
				score = score - 6
				continue
			}
			if strings.Contains(email[i].Result, `"impact":"MEDIUM"`) {
				score = score - 4
				continue
			}
			if strings.Contains(email[i].Result, `"impact":"LOW"`) {
				score = score - 2
				continue
			}
		}

		for i := 0; i < len(http); i++ {
			if strings.Contains(http[i].Result, `"impact":"HIGH"`) {
				score = score - 6
				continue
			}
			if strings.Contains(http[i].Result, `"impact":"MEDIUM"`) {
				score = score - 4
				continue
			}
			if strings.Contains(http[i].Result, `"impact":"LOW"`) {
				score = score - 2
				continue
			}
		}
		for i := 0; i < len(network); i++ {
			if strings.Contains(network[i].Result, `"impact":"HIGH"`) {
				score = score - 6
				continue
			}
			if strings.Contains(network[i].Result, `"impact":"MEDIUM"`) {
				score = score - 4
				continue
			}
			if strings.Contains(network[i].Result, `"impact":"LOW"`) {
				score = score - 2
				continue
			}
		}
		for i := 0; i < len(website); i++ {
			if strings.Contains(website[i].Result, `"impact":"HIGH"`) {
				score = score - 6
				continue
			}
			if strings.Contains(website[i].Result, `"impact":"MEDIUM"`) {
				score = score - 4
				continue
			}
			if strings.Contains(website[i].Result, `"impact":"LOW"`) {
				score = score - 2
				continue
			}
		}

		websiteLoader := true
		emailLoader := true
		networkLoader := true
		HTTPLoader := true
		totalwebsite := 15
		totalemail := 3
		totalnetwork := 2
		totalHTTP := 7

		if totalnetwork-len(network) == 0 {
			networkLoader = false
		}
		if totalwebsite-len(website) == 0 {
			websiteLoader = false
		}
		if totalemail-len(email) == 0 {
			emailLoader = false
		}
		if totalHTTP-len(http) == 0 {
			HTTPLoader = false
		}

		//scriptCount based on totat script and running script
		if (len(website) + len(email) + len(network) + len(http)) == (totalwebsite + totalemail + totalnetwork + totalHTTP) {
			result <- gin.H{
				"error":                   false,
				"website_security":        website,
				"email_security":          email,
				"network_security":        network,
				"http_security":           http,
				"message":                 "Final result",
				"score":                   score,
				"website_security_loader": websiteLoader,
				"email_security_loader":   emailLoader,
				"network_security_loader": networkLoader,
				"http_security_loader":    HTTPLoader,
			}
		} else {
			result <- gin.H{
				"error":                   false,
				"website_security":        website,
				"email_security":          email,
				"network_security":        network,
				"http_security":           http,
				"score":                   score,
				"website_security_loader": websiteLoader,
				"email_security_loader":   emailLoader,
				"network_security_loader": networkLoader,
				"http_security_loader":    HTTPLoader,
			}
		}
		if !websiteLoader && !emailLoader && !networkLoader {
			close(result)
			log.Println(result)
			return
		}
	}
	close(result)
	log.Println(result)
}

func ScanResult(c *gin.Context) {
	chanstream := make(chan interface{})

	// mapd := make(map[string]interface{})

	go fetchFromDatabase(c.Param("id"), chanstream)
	// c.JSON(200, <-chanstream)
	c.Stream(func(w io.Writer) bool {
		if msg, ok := <-chanstream; ok {
			c.SSEvent("message", msg)
			return true
		}
		return false
	})
}

type C struct {
	Vulnerabilities []Link `json:"Vulnerabilities"`
}
type Link struct {
	Documents string `json:"Severity"`
}

func GitScanResult(c *gin.Context) {
	// chanstream := make(chan interface{})
	data := fetchGitResult(c.Param("id"))
	c.JSON(200, data.ResultMapd)
	// c.Stream(func(w io.Writer) bool {
	// 	if msg, ok := <-chanstream; ok
	// 		c.SSEvent("message", msg)
	// 		return true
	// 	}
	// 	return false
	// })
}

func fetchGitResult(uuid string) database.NodeResult {
	// now := time.Now().Unix()
	// end := time.Now().Unix()
	db := config.DB
	// for end-now < 1000 {
	// 	time.Sleep(2 * time.Second)
	// end = time.Now().Unix()
	noderesult := database.NodeResult{}
	db.Where("uuid=?", uuid).Find(&noderesult)
	var mapd []map[string]interface{}
	err := json.Unmarshal([]byte(noderesult.Result), &mapd)

	b, _ := json.Marshal(mapd)
	type n struct {
		Check string `json:"Check"`
	}
	var m []n
	json.Unmarshal(b, &m)
	log.Println(m[0].Check)

	if err != nil {
		log.Println(err)
	}
	noderesult.ResultMapd = mapd
	return noderesult
	// }

}

// TechStack is an api handler to get results from database related to technology stack
func TechStack(c *gin.Context) {
	uuid := c.Param("id")
	db := config.DB
	scanned := database.ScanResult{}
	db.Where("uuid=? AND command_name=?", uuid, "Technology Stack").Find(&scanned)
	if scanned.CommandName == "" {
		c.JSON(200, gin.H{
			"error": false,
			"stack": scanned,
		})
		return
	}
	c.JSON(200, gin.H{
		"error":   false,
		"stack":   scanned,
		"message": "final result",
	})
}
