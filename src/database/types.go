package database

import (
	"fmt"
	"log"
	"time"

	"git.xenonstack.com/util/continuous-security-backend/config"
	"github.com/jinzhu/gorm"
)

// RequestInfo save meta user request infromation
type RequestInfo struct {
	ID        int       `json:"-" gorm:"primary_key"`
	UUID      string    `json:"uid" gorm:"unique_index"`
	IP        string    `json:"ip"`
	Agent     string    `json:"agent"`
	Timestamp int64     `json:"timestamp"`
	URL       string    `json:"url"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"-"`
	UpdatedAt time.Time `json:"-"`
}

// NodeScanInfo save meta user request infromation
type NodeInfo struct {
	ID          int       `json:"_" grom:"primary_key"`
	UUID        string    `json:"uid" gorm:"unique_index"`
	RepoLang    string    `json:"repo_lang"`
	GitURL      string    `json:"git_url" binding:"required"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	ProjectName string    `json:"project_name"`
	Branch      string    `json:"branch"`
	IP          string    `json:"ip"`
	Agent       string    `json:"agent"`
	Timestamp   int64     `json:"timestamp"`
	CreatedAt   time.Time `json:"-"`
	UpdatedAt   time.Time `json:"-"`
}

// ScanResult save web scanned result
type ScanResult struct {
	ID          int       `json:"-" gorm:"primary_key"`
	UUID        string    `json:"uid" gorm:"not null;unique_index:indx_result;"`
	Result      string    `json:"result"`
	CommandName string    `json:"command_name" gorm:"not null;unique_index:indx_result;"`
	Method      string    `json:"-" gorm:"not null;unique_index:indx_result;"`
	CreatedAt   time.Time `json:"-"`
	UpdatedAt   time.Time `json:"-"`
}

// NodeScanResult save web scanned result
type NodeResult struct {
	ID         int         `json:"-" gorm:"primary_key"`
	UUID       string      `json:"uid" gorm:"not null;unique_index:indx_result;"`
	Result     string      `json:"-"`
	ResultMapd interface{} `json:"result"  gorm:"-"`
	CreatedAt  time.Time   `json:"-"`
	UpdatedAt  time.Time   `json:"-"`
}

// CreateDBTablesIfNotExists Initializing Database tables
func CreateDBTablesIfNotExists() {
	db := config.DB

	if !db.HasTable(&RequestInfo{}) {
		db.CreateTable(&RequestInfo{})
	}
	if !db.HasTable(&ScanResult{}) {
		db.CreateTable(&ScanResult{})
	}
	if !db.HasTable(&NodeInfo{}) {
		db.CreateTable(&NodeInfo{})
	}
	if !db.HasTable(&NodeResult{}) {
		db.CreateTable(&NodeResult{})
	}
	db.AutoMigrate(&NodeInfo{}, &NodeResult{}, &ScanResult{}, &RequestInfo{})

	//keys
	db.Model(&ScanResult{}).AddForeignKey("uuid", "request_infos(uuid)", "CASCADE", "CASCADE")
	db.Model(&NodeResult{}).AddForeignKey("uuid", "node_infos(uuid)", "CASCADE", "CASCADE")

	log.Println("Database initialized successfully.")
}

// CreateDatabase Initializing Database
func CreateDatabase() {
	// connecting with cockroach database root db
	db, err := gorm.Open("postgres", fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		config.Conf.Database.Host,
		config.Conf.Database.Port,
		config.Conf.Database.User,
		config.Conf.Database.Pass,
		"postgres", config.Conf.Database.Ssl))
	if err != nil {
		log.Println(err)
		return
	}
	defer db.Close()

	// executing create database query.
	db.Exec(fmt.Sprintf("create database %s;", config.Conf.Database.Name))
}
