package database

import (
	"fmt"
	"log"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"

	"git.xenonstack.com/util/continuous-security-backend/config"
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
type NodeScanInfo struct {
	ID          int       `json:"_" grom:"primary_key"`
	UUID        string    `json:"uid" gorm:"unique_index"`
	IP          string    `json:"ip"`
	Agent       string    `json:"agent"`
	Timestamp   int64     `json:"timestamp"`
	GitURL      string    `json:"git_url"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	ProjectName string    `json:"project_name"`
	Branch      string    `json:"branch"`
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
type NodeScanResult struct {
	ID          int       `json:"-" gorm:"primary_key"`
	UUID        string    `json:"uid" gorm:"not null;unique_index:indx_result;"`
	Result      string    `json:"result"`
	CommandName string    `json:"command_name" gorm:"not null;unique_index:indx_result;"`
	Method      string    `json:"-" gorm:"not null;unique_index:indx_result;"`
	CreatedAt   time.Time `json:"-"`
	UpdatedAt   time.Time `json:"-"`
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
	if !db.HasTable(&NodeScanInfo{}) {
		db.Create(&NodeScanInfo{})
	}
	if !db.HasTable(&NodeScanResult{}) {
		db.Create(&NodeScanResult{})
	}

	db.AutoMigrate(&RequestInfo{}, &ScanResult{}, &NodeScanInfo{}, &NodeScanResult{})

	//keys
	db.Model(&ScanResult{}).AddForeignKey("uuid", "request_infos(uuid)", "CASCADE", "CASCADE")
	// db.Model(&NodeScanResult{}).AddForeignKey("uuid", "NodeScanInfo(uuid)", "CASCADE", "CASCADE")

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
